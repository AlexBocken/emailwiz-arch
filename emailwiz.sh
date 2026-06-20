#!/bin/sh

# THE SETUP

# Mail will be stored in non-retarded Maildirs because it's $currentyear. This
# makes it easier for use with isync, which is what I care about so I can have
# an offline repo of mail.

# The mailbox names are: Inbox, Sent, Drafts, Archive, Junk, Trash

# Use the typical unix login system for mail users. Users will log into their
# email with their passnames on the server. No usage of a redundant mySQL
# database to do this.

# DEPENDENCIES BEFORE RUNNING

# 1. Have a Arch system with a static IP and all that. Pretty much any
# default VPS offered by a company will have all the basic stuff you need.

# 2. Have a Let's Encrypt SSL certificate for $maildomain. You might need one
# for $domain as well, but they're free with Let's Encypt so you should have
# them anyway.

# 3. If you've been toying around with your server settings trying to get
# postfix/dovecot/etc. working before running this, I recommend you `pacman -Rn`
# everything first because this script is build on top of only the defaults.
# Clear out /etc/postfix and /etc/dovecot yourself if needbe.

echo 'Installing programs...'
pacman -Syu --needed postfix dovecot opendkim spamassassin pigeonhole certbot clamav
# Put your domain.tld here (not your subdomain)
domain='domain.tld'

[ "$domain" = "domain.tld" ] && echo 'Fill in your domain name!' && exit 1

subdom=${MAIL_SUBDOM:-mail}
maildomain="$subdom.$domain"
certdir="/etc/letsencrypt/live/$maildomain"

[ ! -d "$certdir" ] && certdir="$(dirname "$(certbot certificates 2>/dev/null | grep -A 2 "$maildomain\|*.$domain" | awk '/Certificate Path/ {print $3}' | head -n1)")"

[ ! -d "$certdir" ] && echo "Note! You must first have a Let's Encrypt Certbot HTTPS/SSL Certificate for $maildomain.

Use Let's Encrypt's Certbot to get that and then rerun this script.

You may need to set up a dummy $maildomain site in nginx or Apache for that to work." && exit 1

# NOTE ON POSTCONF COMMANDS

# The `postconf` command literally just adds the line in question to
# /etc/postfix/main.cf so if you need to debug something, go there. It replaces
# any other line that sets the same setting, otherwise it is appended to the
# end of the file.

echo "Configuring Postfix's main.cf..."

# Necessary to later start Postfix
postalias /etc/postfix/aliases

# List of domains that this machine considers itself the final destination for
postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain'

# Change the cert/key files to the default locations of the Let's Encrypt cert/key
postconf -e "smtpd_tls_key_file=$certdir/privkey.pem"
postconf -e "smtpd_tls_cert_file=$certdir/fullchain.pem"
postconf -e "smtp_tls_CAfile=$certdir/cert.pem"

# DH parameters: no longer set in Postfix. Since 3.9 the
# smtpd_tls_dh1024_param_file parameter is deprecated (slated for removal) and
# Postfix negotiates DH via its built-in FFDHE groups by default. The dh.pem
# generated below is still used by Dovecot (ssl_dh).

# Enable, but do not require TLS. Requiring it with other server would cause
# mail delivery problems and requiring it locally would cause many other
# issues.
postconf -e 'smtpd_tls_security_level = may'
postconf -e 'smtp_tls_security_level = may'

# TLS required for authentication.
postconf -e 'smtpd_tls_auth_only = yes'

# Exclude obsolete, insecure and obsolete encryption protocols.
postconf -e 'smtpd_tls_mandatory_protocols = >=TLSv1.2, <=TLSv1.3'
postconf -e 'smtp_tls_mandatory_protocols = >=TLSv1.2, <=TLSv1.3'
postconf -e 'smtpd_tls_protocols = >=TLSv1.2, <=TLSv1.3'
postconf -e 'smtp_tls_protocols = >=TLSv1.2, <=TLSv1.3'

# Exclude suboptimal ciphers.
postconf -e 'tls_preempt_cipherlist = yes'
postconf -e 'smtpd_tls_ciphers = high'
postconf -e 'smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, LOW, EXP, MEDIUM, ADH, AECDH, DSS, ECDSA, CAMELLIA128, 3DES, CAMELLIA256, RSA+AES, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3-SHA, SHA1, SHA256, SHA384'
# Disable insecure renegotiation
postconf -e 'tls_ssl_options = NO_RENEGOTIATION'

# Here we tell Postfix to look to Dovecot for authenticating users/passwords.
# Dovecot will be putting an authentication socket in /var/spool/postfix/private/auth
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/auth'

# Anti-relay hardening: accept mail only from authenticated users, from our own
# networks, or for domains we are responsible for, and reject recipients in
# non-resolvable domains. Without this an open-relay misconfiguration is easy.
postconf -e 'smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination, reject_unknown_recipient_domain'

# Hardening: do not leak whether an address exists via the SMTP VRFY command.
postconf -e 'disable_vrfy_command = yes'

# Hide the Postfix version/mail_name in the SMTP banner.
postconf -e 'smtpd_banner = $myhostname ESMTP'

# Allow larger messages/attachments (~50 MB) instead of the 10 MB default.
postconf -e 'message_size_limit = 51200000'

# Virtual alias map for address forwarding (e.g. dmarc@, postmaster@).
# Create the table if absent and compile it so lookups don't error.
[ -f /etc/postfix/virtual ] || touch /etc/postfix/virtual
postconf -e 'virtual_alias_maps = lmdb:/etc/postfix/virtual'
postmap /etc/postfix/virtual

# Prevent IP address leaks (also removes ip from incoming email)
postconf -e 'header_checks = regexp:/etc/postfix/header_checks'

echo '/^Received: .*/       IGNORE
/^User-Agent: .*/     IGNORE
/^X-Originating-IP:/  IGNORE' >> /etc/postfix/header_checks

# NOTE: the trailing slash here, or for any directory name in the home_mailbox
# command, is necessary as it distinguishes a maildir (which is the actual
# directories that what we want) from a spoolfile (which is what old unix
# boomers want and no one else).
postconf -e 'home_mailbox = Mail/Inbox/'

# master.cf
echo "Configuring Postfix's master.cf..."

sed -i '/^\s*-o/d;/^\s*submission/d;/^\s*smtp/d' /etc/postfix/master.cf

echo 'smtp      unix  -       -       n       -       -       smtp
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamassassin
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
spamassassin unix -     n       n       -       -       pipe
  flags=R user=spamd argv=/usr/bin/vendor_perl/spamc -e /usr/bin/sendmail -oi -f ${sender} ${recipient}' >> /etc/postfix/master.cf


# By default, Dovecot has a bunch of example configs in `/usr/share/doc/dovecot/example-config/` These
# files have nice documentation if you want to read it, but it's a huge pain to go through them to organize.
# Instead, we simply use /etc/dovecot/dovecot.conf because it's easier to manage.

echo 'Generating a DH parameters file for Dovecot...'

mkdir -p /etc/dovecot
openssl dhparam -out /etc/dovecot/dh.pem 3072

echo 'Creating Dovecot config...'

# The IMAPSieve auto-learn blocks below need Dovecot/Pigeonhole >= 2.4.3. On
# 2.4.1-2.4.2 the admin-scoped mailbox { sieve_script } blocks SILENTLY no-op
# (the move succeeds, the script never fires, Bayes is never updated), so warn
# loudly rather than leave the user with broken-but-quiet auto-learning.
dovecot_version="$(dovecot --version 2>/dev/null | awk '{print $1}')"
if [ -n "$dovecot_version" ] &&
	[ "$(printf '2.4.3\n%s\n' "$dovecot_version" | sort -V | head -n1)" != '2.4.3' ]; then
	printf '\033[31mWARNING:\033[0m Dovecot %s < 2.4.3 — IMAPSieve spam/ham auto-learning will silently no-op.\n' "$dovecot_version"
fi

echo "# Note that in the Dovecot conf, you can use:
# %u for username
# %n for the name in name@domain.tld
# %d for the domain
# %h the user's home directory

# If you're not a brainlet, SSL must be set to required.
ssl = required
ssl_cert = <$certdir/fullchain.pem
ssl_key = <$certdir/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list=ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!LOW:!MEDIUM:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SHA1:!SHA256:!SHA384
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
# Plaintext login. This is safe and easy thanks to SSL.
auth_mechanisms = plain login
auth_username_format = %n

protocols = imap lmtp

# Search for valid users in /etc/passwd
userdb {
	driver = passwd
}

# Fallback: Use plain old PAM to find user passwords
passdb {
	driver = pam
}

# Our mail for each user will be in ~/Mail, and the inbox will be ~/Mail/Inbox
# The LAYOUT option is also important because otherwise, the boxes will be \`.Sent\` instead of \`Sent\`.
mail_location = maildir:~/Mail:INBOX=~/Mail/Inbox:LAYOUT=fs
namespace inbox {
	inbox = yes

	mailbox Drafts {
		special_use = \\Drafts
		auto = subscribe
	}

	mailbox Junk {
		special_use = \\Junk
		auto = subscribe

		# Filing a message into Junk trains it as spam (IMAPSieve auto-learn).
		# cause = append copy is essential: many IMAP clients move into Junk via
		# APPEND, not COPY, and a copy-only rule would never fire for them.
		sieve_script learn-spam {
			type = before
			cause = append copy
			path = /var/lib/dovecot/sieve/learn-spam.sieve
		}
	}

	mailbox Sent {
		special_use = \\Sent
		auto = subscribe
	}

	mailbox Trash {
		special_use = \\Trash
	}

	mailbox Archive {
		special_use = \\Archive
	}
}

# IMAPSieve auto-learn (Dovecot 2.4 syntax). The learner runs as the mailbox
# user, so it never touches the Bayes DB directly: it pipes the message to
# spamc --learntype and spamd (running with --allow-tell) does the privileged
# learning. This is why no Bayes-DB permissions need opening to mail users.
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

# Moving a message OUT of Junk trains it as ham. This matches on the source
# mailbox; it is best-effort with APPEND-based clients (an APPEND carries no
# origin). Spam (into Junk) is the reliable, important direction.
imapsieve_from Junk {
	sieve_script learn-ham {
		type = before
		cause = copy
		path = /var/lib/dovecot/sieve/learn-ham.sieve
	}
}

# Here we let Postfix use Dovecot's authetication system.

service auth {
	unix_listener /var/spool/postfix/private/auth {
		mode = 0660
		user = postfix
		group = postfix
	}
}

protocol lmtp {
	mail_plugins = \$mail_plugins sieve
}

plugin {
	sieve_default = /var/lib/dovecot/sieve/default.sieve
	sieve_global = /var/lib/dovecot/sieve/
}" > /etc/dovecot/dovecot.conf

mkdir -p /var/lib/dovecot/
mkdir -p /var/lib/dovecot/sieve/

echo "require [\"fileinto\", \"mailbox\"];
if header :contains \"X-Spam-Flag\" \"YES\"
	{
		fileinto \"Junk\";
	}" > /var/lib/dovecot/sieve/default.sieve

grep -q '^vmail:' /etc/passwd || useradd vmail
chown -R vmail:vmail /var/lib/dovecot
sievec /var/lib/dovecot/sieve/default.sieve

# --- IMAPSieve auto-learn: pipe scripts + sieve sources ---
# The pipe scripts are executed AS THE MAILBOX USER but are shared globally, so
# they must be root:root, world read+exec, and never writable by mail users (a
# writable pipe script = code execution in the user's IMAP session). Dovecot's
# extprograms also refuses loosely-permissioned scripts, so 0755 (not 0775/0777).
# Full /usr/bin/vendor_perl/ path: spamc is not on PATH in Dovecot's restricted
# exec environment on Arch.
mkdir -p /usr/lib/dovecot/sieve
printf '#!/bin/sh\nexec /usr/bin/vendor_perl/spamc --learntype=spam --username spamd\n' \
	> /usr/lib/dovecot/sieve/learn-spam.sh
printf '#!/bin/sh\nexec /usr/bin/vendor_perl/spamc --learntype=ham --username spamd\n' \
	> /usr/lib/dovecot/sieve/learn-ham.sh
chown root:root /usr/lib/dovecot/sieve/learn-spam.sh /usr/lib/dovecot/sieve/learn-ham.sh
chmod 0755 /usr/lib/dovecot/sieve/learn-spam.sh /usr/lib/dovecot/sieve/learn-ham.sh

# Sieve sources. The Trash guard on the ham learner avoids mislearning ham when
# spam is merely being deleted out of Junk.
printf 'require ["vnd.dovecot.pipe", "copy", "imapsieve"];\npipe :copy "learn-spam.sh";\n' \
	> /var/lib/dovecot/sieve/learn-spam.sieve
printf 'require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment"];\nif environment :is "imap.mailbox" "Trash" { stop; }\npipe :copy "learn-ham.sh";\n' \
	> /var/lib/dovecot/sieve/learn-ham.sieve

# Standalone sievec doesn't load the imapsieve/extprograms plugins, so name them
# explicitly with -P. The + prefix ADDS the extensions instead of replacing the
# default set (without + you lose copy/environment). Pre-compiling matters: the
# source dir is root-owned, so without a prebuilt .svbin Dovecot (running as the
# mail user) recompiles on every trigger and logs a permission warning each time.
for s in learn-spam learn-ham; do
	sievec -P sieve_imapsieve -P sieve_extprograms -x '+imapsieve +vnd.dovecot.pipe' \
		"/var/lib/dovecot/sieve/$s.sieve"
done
chmod 0644 /var/lib/dovecot/sieve/learn-spam.svbin /var/lib/dovecot/sieve/learn-ham.svbin

echo 'Preparing user authentication...'

grep -q nullok /etc/pam.d/dovecot ||
echo 'auth    required pam_unix.so nullok
account required pam_unix.so' >> /etc/pam.d/dovecot

# OpenDKIM

# A lot of the big name email services, like Google, will automatically reject
# as spam unfamiliar and unauthenticated email addresses. As in, the server
# will flatly reject the email, not even delivering it to someone's Spam
# folder.

# OpenDKIM is a way to authenticate your email so you can send to such services
# without a problem.

# Create an OpenDKIM key
echo 'Generating OpenDKIM keys...'
mkdir -p /etc/postfix/dkim
opendkim-genkey -D /etc/postfix/dkim -d "$domain" -s "$subdom"

# Generate the OpenDKIM info:
echo 'Configuring OpenDKIM...'

grep -q "$domain" /etc/postfix/dkim/keytable 2>/dev/null ||
echo "$subdom._domainkey.$domain $domain:$subdom:/etc/postfix/dkim/$subdom.private" >> /etc/postfix/dkim/keytable

grep -q "$domain" /etc/postfix/dkim/signingtable 2>/dev/null ||
echo "*@$domain $subdom._domainkey.$domain" >> /etc/postfix/dkim/signingtable

grep -q '127.0.0.1' /etc/postfix/dkim/trustedhosts 2>/dev/null ||
echo '127.0.0.1' >> /etc/postfix/dkim/trustedhosts

# ...and source it from opendkim.conf
grep -q '^KeyTable' /etc/opendkim/opendkim.conf 2>/dev/null ||
echo "KeyTable file:/etc/postfix/dkim/keytable
SigningTable refile:/etc/postfix/dkim/signingtable
InternalHosts refile:/etc/postfix/dkim/trustedhosts
Domain $domain" >> /etc/opendkim/opendkim.conf

sed -i '/^#Canonicalization/s/simple/relaxed\/simple/' /etc/opendkim/opendkim.conf
sed -i '/^#Canonicalization/s/^#//' /etc/opendkim/opendkim.conf

sed -i '/Socket/s/^#*/#/' /etc/opendkim/opendkim.conf
grep -q '^Socket\s*inet:12301@localhost' /etc/opendkim/opendkim.conf ||
echo 'Socket inet:12301@localhost' >> /etc/opendkim/opendkim.conf

# Here we add to postconf the needed settings for working with OpenDKIM
echo 'Configuring Postfix with OpenDKIM settings...'
postconf -e 'smtpd_sasl_security_options = noanonymous, noplaintext'
postconf -e 'smtpd_sasl_tls_security_options = noanonymous'
postconf -e "myhostname = $maildomain"
postconf -e 'milter_default_action = accept'
postconf -e 'milter_protocol = 6'
# smtpd_milters / non_smtpd_milters are LISTS: chain ClamAV after the OpenDKIM
# milter. A second standalone line would silently override the first and disable
# OpenDKIM. milter_default_action = accept (set above) means fail-open if a milter
# is unreachable. DKIM-then-ClamAV order is fine; they are independent.
postconf -e 'smtpd_milters = inet:localhost:12301, unix:/var/spool/postfix/private/clamav-milter'
postconf -e 'non_smtpd_milters = inet:localhost:12301, unix:/var/spool/postfix/private/clamav-milter'
postconf -e 'mailbox_command = /usr/lib/dovecot/deliver'

useradd -mG mail dmarc

# SpamAssassin: Bayes + delegated learning
echo 'Configuring SpamAssassin for Bayes auto-learning...'

# sa-update and the Bayes DB are written by the spamd user; the whole state tree
# must be spamd-owned or updates/learning fail with permission errors.
chown -R spamd:spamd /var/lib/spamassassin

# Make sure Bayes is on — the IMAPSieve learners are pointless without it. Note
# Bayes only starts scoring after >=200 spam AND >=200 ham have been learned, so
# expect no effect until the corpus (seeded by the learners over time) is built.
mkdir -p /etc/mail/spamassassin
grep -q '^use_bayes ' /etc/mail/spamassassin/local.cf 2>/dev/null ||
printf 'use_bayes 1\nbayes_auto_learn 1\n' >> /etc/mail/spamassassin/local.cf

# spamc --learntype (used by the Dovecot pipe scripts) only works if spamd runs
# with --allow-tell. Re-declare ExecStart with the package's existing options
# plus --allow-tell, reading the base command from the shipped unit rather than
# hardcoding flags that vary by package version.
mkdir -p /etc/systemd/system/spamassassin.service.d
sa_exec="$(systemctl cat spamassassin.service | sed -n 's/^ExecStart=//p' | grep -v '^$' | tail -n1)"
case "$sa_exec" in
	*--allow-tell*) : ;;
	*) sa_exec="$sa_exec --allow-tell" ;;
esac
printf '[Service]\nExecStart=\nExecStart=%s\n' "$sa_exec" \
	> /etc/systemd/system/spamassassin.service.d/override.conf
systemctl daemon-reload

# ClamAV milter: scan mail during the SMTP transaction and reject infected mail
# before it is ever written to a mailbox. The milter talks to clamd. The Arch
# clamav package ships clamd (clamav-daemon.service) and freshclam but NOT a
# milter service, so we create the unit ourselves.
echo 'Configuring ClamAV milter...'

# Milter config. The reject message is generic on purpose: no virus name, no
# "ClamAV"/"virus" wording, so the bounce can't fingerprint the scanner or act as
# a tuning oracle. AddHeader No keeps X-Virus-* headers (tool/version/host) off
# outbound mail — privacy, and it avoids header rewrites that can break DKIM.
# OnFail Defer temp-fails (4xx) if clamd is down so nothing slips through
# unscanned. ClamdSocket matches clamav-daemon.socket's /run/clamav/clamd.ctl.
cat > /etc/clamav/clamav-milter.conf <<'EOF'
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
EOF
chmod 0644 /etc/clamav/clamav-milter.conf

# Milter service. It must start as root so it can bind its socket inside
# Postfix's root-owned private/ dir, then it drops to the User clamav from the
# conf above. Do NOT add User= here or socket creation breaks.
cat > /etc/systemd/system/clamav-milter.service <<'EOF'
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
EOF
chmod 0644 /etc/systemd/system/clamav-milter.service

# Ensure the runtime/state dirs exist before starting anything (the pacman
# tmpfiles hook normally handles this; be defensive on a fresh install).
systemd-tmpfiles --create clamav.conf

# clamd refuses to start without a virus database, so pull one now. Run as root;
# freshclam drops to the clamav DatabaseOwner for the actual file writes.
echo 'Downloading initial ClamAV virus database (this may take a while)...'
freshclam

# Postfix must be in the clamav group to read the 660 milter socket. Supplementary
# group membership is fixed at process start, so a FULL postfix restart (below) is
# required — a reload leaves the socket Permission denied and mail goes unscanned.
gpasswd -a postfix clamav

systemctl daemon-reload

systemctl enable --now clamav-daemon clamav-freshclam clamav-milter spamassassin opendkim dovecot postfix
# Ensure the --allow-tell ExecStart is live even on a re-run where spamd was
# already running (enable --now won't restart an active unit).
systemctl restart spamassassin
# Full restart (not reload) so postfix picks up its new clamav group membership.
systemctl restart postfix

pval="$(tr -d "\n" </etc/postfix/dkim/$subdom.txt | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o "p=.*")"
dkimentry="$subdom._domainkey.$domain	TXT	v=DKIM1; k=rsa; $pval"
dmarcentry="_dmarc.$domain	TXT	v=DMARC1; p=reject; rua=mailto:dmarc@$domain; fo=1"
spfentry="$domain	TXT	v=spf1 mx a:$maildomain -all"

echo "$dkimentry
$dmarcentry
$spfentry" > "$HOME/dns_emailwizard"

## Fix permissions for opendkim
chown opendkim:opendkim "/etc/postfix/dkim/${subdom}.private" "/etc/postfix/dkim/${subdom}.txt"

printf "\033[31m
 _   _
| \ | | _____      ___
|  \| |/ _ \ \ /\ / (_)
| |\  | (_) \ V  V / _
|_| \_|\___/ \_/\_/ (_)\033[0m

Add these three records to your DNS TXT records on either your registrar's site
or your DNS server:
\033[32m
$dkimentry

$dmarcentry

Note: You will probably need to modify this later (eg. adding your ip)
$spfentry
\033[0m
NOTE: You may need to omit the \`.$domain\` portion at the beginning if
inputting them in a registrar's web interface.

Also, these are now saved to \033[34m~/dns_emailwizard\033[0m in case you want them in a file.

Once you do that, you're done! Check the README for how to add users/accounts
and how to log in.\n"
