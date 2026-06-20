# Enabling SpamAssassin Bayes auto-learning after the fact

`emailwiz.sh` sets this up on a fresh install. If you already ran an older
version of the script, the steps below add the same active spam/ham learning to
a **running** server without re-running the whole script.

What you get: filing a message into **Junk** trains SpamAssassin's Bayes filter
as spam; moving one back out trains it as ham. The learner runs as the mailbox
user but never touches the Bayes DB directly — it pipes the message to `spamc`,
and `spamd` (running with `--allow-tell`) does the privileged learning.

## Preconditions

- **Dovecot/Pigeonhole ≥ 2.4.3.** On 2.4.1–2.4.2 the admin-scoped
  `mailbox { sieve_script }` blocks **silently no-op** (the move succeeds, the
  script never fires, Bayes is never updated). Check with `dovecot --version`.
- `spamassassin` and `pigeonhole` installed, `spamd` running.
- The Junk mailbox is named `Junk` with `special_use = \Junk`.

### Arch path note

SpamAssassin binaries live under **`/usr/bin/vendor_perl/`**, not `/usr/bin`.
They're on `PATH` in an interactive shell but **not** in Dovecot's restricted
exec environment, so the pipe scripts below use the full path.

---

## 1. SpamAssassin: state dir, Bayes, and `--allow-tell`

```bash
# sa-update and the Bayes DB are written by the spamd user; the whole tree must
# be spamd-owned or learning fails with permission errors.
chown -R spamd:spamd /var/lib/spamassassin

# Make sure Bayes is on (the learners are pointless without it).
mkdir -p /etc/mail/spamassassin
grep -q '^use_bayes ' /etc/mail/spamassassin/local.cf 2>/dev/null ||
printf 'use_bayes 1\nbayes_auto_learn 1\n' >> /etc/mail/spamassassin/local.cf
```

`spamc --learntype` only works if `spamd` runs with `--allow-tell`. Add a
systemd drop-in that re-declares `ExecStart` with the package's existing options
**plus** `--allow-tell` (read the base command from the shipped unit rather than
hardcoding flags, which vary by package version):

```bash
mkdir -p /etc/systemd/system/spamassassin.service.d
sa_exec="$(systemctl cat spamassassin.service | sed -n 's/^ExecStart=//p' | grep -v '^$' | tail -n1)"
case "$sa_exec" in
	*--allow-tell*) : ;;
	*) sa_exec="$sa_exec --allow-tell" ;;
esac
printf '[Service]\nExecStart=\nExecStart=%s\n' "$sa_exec" \
	> /etc/systemd/system/spamassassin.service.d/override.conf

systemctl daemon-reload
systemctl restart spamassassin
pgrep -af spamd | grep -- --allow-tell   # verify it took
```

The empty `ExecStart=` line resets the inherited command before the new one —
without it systemd errors on the second `ExecStart`.

---

## 2. Dovecot IMAPSieve: pipe scripts + sieve sources

The pipe scripts are executed **as the mailbox user** but are shared globally,
so they must be `root:root`, world read+exec, and never writable by mail users
(a writable pipe script = code execution in the user's IMAP session). Dovecot's
extprograms also refuses loosely-permissioned scripts — use `0755`.

```bash
mkdir -p /usr/lib/dovecot/sieve
printf '#!/bin/sh\nexec /usr/bin/vendor_perl/spamc --learntype=spam --username spamd\n' \
	> /usr/lib/dovecot/sieve/learn-spam.sh
printf '#!/bin/sh\nexec /usr/bin/vendor_perl/spamc --learntype=ham --username spamd\n' \
	> /usr/lib/dovecot/sieve/learn-ham.sh
chown root:root /usr/lib/dovecot/sieve/learn-spam.sh /usr/lib/dovecot/sieve/learn-ham.sh
chmod 0755 /usr/lib/dovecot/sieve/learn-spam.sh /usr/lib/dovecot/sieve/learn-ham.sh
```

The sieve sources. The Trash guard on the ham learner avoids mislearning ham
when spam is merely being deleted out of Junk:

```bash
printf 'require ["vnd.dovecot.pipe", "copy", "imapsieve"];\npipe :copy "learn-spam.sh";\n' \
	> /var/lib/dovecot/sieve/learn-spam.sieve
printf 'require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment"];\nif environment :is "imap.mailbox" "Trash" { stop; }\npipe :copy "learn-ham.sh";\n' \
	> /var/lib/dovecot/sieve/learn-ham.sieve
```

Pre-compile them. Standalone `sievec` doesn't load the imapsieve/extprograms
plugins, so name them with `-P`; the `+` prefix **adds** the extensions instead
of replacing the default set (without `+` you lose `copy`/`environment`).
Pre-compiling matters: the source dir is root-owned, so without a prebuilt
`.svbin` Dovecot recompiles on every trigger and logs a permission warning:

```bash
for s in learn-spam learn-ham; do
	sievec -P sieve_imapsieve -P sieve_extprograms -x '+imapsieve +vnd.dovecot.pipe' \
		"/var/lib/dovecot/sieve/$s.sieve"
done
chmod 0644 /var/lib/dovecot/sieve/learn-spam.svbin /var/lib/dovecot/sieve/learn-ham.svbin
```

---

## 3. Dovecot config

Add the following to `/etc/dovecot/dovecot.conf`.

Inside the existing `namespace inbox { ... }` block, extend the `mailbox Junk`
entry — `cause = append copy` is essential, because many IMAP clients move into
Junk via APPEND, not COPY, and a copy-only rule would never fire for them:

```
mailbox Junk {
	special_use = \Junk
	auto = subscribe
	sieve_script learn-spam {
		type = before
		cause = append copy
		path = /var/lib/dovecot/sieve/learn-spam.sieve
	}
}
```

At the top level (outside any namespace), add:

```
protocol imap {
	mail_plugins {
		imap_sieve = yes
	}
}

sieve_plugins {
	sieve_imapsieve = yes
	sieve_extprograms = yes
}

sieve_global_extensions {
	vnd.dovecot.pipe = yes
}

sieve_pipe_bin_dir = /usr/lib/dovecot/sieve

# Moving a message OUT of Junk learns ham. Matches on the source mailbox, so it
# is best-effort with APPEND-based clients (an APPEND carries no origin). Spam
# (into Junk) is the reliable, important direction.
imapsieve_from Junk {
	sieve_script learn-ham {
		type = before
		cause = copy
		path = /var/lib/dovecot/sieve/learn-ham.sieve
	}
}
```

IMAPSieve config changes need a **full restart**, not a reload:

```bash
systemctl restart dovecot
```

---

## 4. Verify

Drag a *fresh* spam message into Junk and watch the log:

```bash
journalctl -u dovecot -f
```

Expect `sieve: action pipe: running program: learn-spam.sh` followed by
`Finished executing pipe action (status=ok)`. Then confirm Bayes saw it:

```bash
sudo -u spamd /usr/bin/vendor_perl/sa-learn --dump magic   # nspam should increment
```

(A message already in the DB returns 0 without incrementing — that's normal.)

## Note on Bayes activation

Bayes only starts scoring after **≥200 spam AND ≥200 ham** have been learned. A
fresh or lopsided DB contributes nothing until the corpus is built up — the
learners seed it over time as you file mail. If you have an existing spam corpus
you can seed it directly:

```bash
sudo -u spamd /usr/bin/vendor_perl/sa-learn --spam --progress <spam-maildir>
```

The ham direction is best-effort with APPEND-based clients; you can supplement it
with a periodic `sa-learn --ham` over your inbox.
