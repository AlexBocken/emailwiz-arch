# Enabling ClamAV malware scanning after the fact

`emailwiz.sh` sets this up on a fresh install. If you already ran an older
version of the script, the steps below add ClamAV virus scanning to a
**running** server without re-running the whole script.

What you get: mail is scanned during the SMTP transaction by a ClamAV milter.
Infected messages are **rejected before delivery**, so they never land in a
mailbox (no Maildir corruption). The milter talks to the `clamd` daemon.

## Preconditions

- The Arch `clamav` package ships `clamd` (`clamav-daemon.service`) and
  `freshclam`, but **no milter service** — you create that unit yourself (below).
- An existing milter is already wired into Postfix (this setup uses **OpenDKIM**
  on `inet:localhost:12301`). Don't clobber it — chain ClamAV onto it.

```bash
pacman -S --needed clamav
```

---

## 1. Milter config — `/etc/clamav/clamav-milter.conf`

Owner `root:root`, mode `0644`.

```ini
MilterSocket /var/spool/postfix/private/clamav-milter
MilterSocketMode 660
MilterSocketGroup clamav
FixStaleSocket yes
User clamav
ClamdSocket unix:/run/clamav/clamd.ctl
OnInfected Reject
RejectMsg "Message rejected by content policy"
OnFail Defer
AddHeader No
LogSyslog yes
LogInfected Full
PidFile /run/clamav/clamav-milter.pid
TemporaryDirectory /tmp
```

Why these values matter:

- **`OnInfected Reject`** — bounce infected mail at SMTP time (sender gets an NDR).
- **`RejectMsg`** is generic on purpose — no `%v` virus name, no "ClamAV"/"virus"
  wording, so the reject doesn't fingerprint the scanner or act as a tuning oracle.
- **`OnFail Defer`** — if `clamd` is down, temp-fail (4xx) so nothing slips
  through unscanned. (Use `Accept` only if you prefer never delaying mail over
  scan coverage.)
- **`AddHeader No`** — critical for privacy: `Add`/`Replace` would stamp
  `X-Virus-Scanned` / `X-Virus-Status` headers (tool name, version, hostname)
  onto every clean message that leaves the server. `No` keeps your stack off
  outbound mail and avoids header rewrites that can break DKIM signatures.
- `ClamdSocket` matches Arch's `clamav-daemon.socket` (`/run/clamav/clamd.ctl`).
- The socket lives in `/var/spool/postfix/private/` so it's reachable whether or
  not smtpd is chrooted.

---

## 2. Milter service — `/etc/systemd/system/clamav-milter.service`

Owner `root:root`, mode `0644`.

```ini
[Unit]
Description=ClamAV Milter (clamav-milter)
Requires=clamav-daemon.service
After=clamav-daemon.service
Before=postfix.service

[Service]
Type=forking
PIDFile=/run/clamav/clamav-milter.pid
ExecStart=/usr/bin/clamav-milter --config-file /etc/clamav/clamav-milter.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

- **Do NOT add `User=clamav` to the unit.** clamav-milter must start as **root**
  so it can bind its socket inside Postfix's root-owned `private/` dir, then it
  drops to the `User clamav` from the conf. Setting `User=` here breaks socket
  creation.
- On Arch the clamd unit is `clamav-daemon.service` — match `Requires=`/`After=`.

---

## 3. Pull a virus database and start the daemons

`clamd` refuses to start without a database, so seed one first:

```bash
systemd-tmpfiles --create clamav.conf   # ensure /run/clamav, /var/lib/clamav exist
freshclam                               # downloads the initial DB (can take a while)

systemctl daemon-reload
systemctl enable --now clamav-daemon clamav-freshclam clamav-milter
```

`clamav-freshclam.service` keeps the database updated from then on.

---

## 4. Wire the milter into Postfix

`smtpd_milters` / `non_smtpd_milters` are **lists** — append ClamAV to the
existing OpenDKIM milter. A second standalone line silently overrides the first
and disables OpenDKIM.

```bash
postconf -e 'smtpd_milters = inet:localhost:12301, unix:/var/spool/postfix/private/clamav-milter'
postconf -e 'non_smtpd_milters = inet:localhost:12301, unix:/var/spool/postfix/private/clamav-milter'
postconf -e 'milter_default_action = accept'   # fail-open if a milter is unreachable
postconf -e 'milter_protocol = 6'
```

(`inet:localhost:12301` is the pre-existing OpenDKIM milter. Check your current
`postconf smtpd_milters` and append rather than assuming the port.)

---

## 5. Socket permission for Postfix

The milter socket is group `clamav`, mode `660`. The `postfix` user must be in
the `clamav` group to read it. Group membership is fixed at process start, so a
**full restart** is required — a `reload` leaves the socket `Permission denied`
and Postfix fails open (mail delivered unscanned):

```bash
gpasswd -a postfix clamav
systemctl restart postfix      # FULL restart, not reload
```

---

## 6. Verify

Send the EICAR test file through and expect a `5xx` reject:

```bash
swaks --to you@yourdomain --from test@example.com --server localhost \
      --attach @/path/to/eicar.com.txt
```

(EICAR is a harmless standard antivirus test string from secure.eicar.org.)

Also check the milter is up and the socket exists:

```bash
systemctl status clamav-milter
ls -l /var/spool/postfix/private/clamav-milter   # srw-rw---- root clamav
journalctl -u clamav-milter -f
```
