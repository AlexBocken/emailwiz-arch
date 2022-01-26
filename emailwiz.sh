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
# default VPS offered by a company will have all the basic stuff you need. This
# script might run on Artix as well. Haven't tried it. If you have, tell me
# what happens.

# 2. Have a Let's Encrypt SSL certificate for $maildomain. You might need one
# for $domain as well, but they're free with Let's Encypt so you should have
# them anyway.

# 3. If you've been toying around with your server settings trying to get
# postfix/dovecot/etc. working before running this, I recommend you `pacman -Rn`
# everything first because this script is build on top of only the defaults.
# Clear out /etc/postfix and /etc/dovecot yourself if needbe.

echo 'Installing programs...'
pacman -Syu --needed postfix dovecot opendkim spamassassin pigeonhole
# Put your domain.tld here (not your subdomain)
domain='domain.tld'
subdom=${MAIL_SUBDOM:-mail}
maildomain="$subdom.$domain"
certdir="/etc/letsencrypt/live/$maildomain"

[ ! -d "$certdir" ] && certdir="$(dirname "$(certbot certificates 2>/dev/null | grep "$maildomain\|*.$domain" -A 2 | awk '/Certificate Path/ {print $3}' | head -n1)")"

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

# DH parameters
postconf -e 'smtpd_tls_dh1024_param_file = /etc/dovecot/dh.pem'

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
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
spamassassin unix -     n       n       -       -       pipe
  flags=R user=spamd argv=/usr/bin/vendor_perl/spamc -e /usr/bin/sendmail -oi -f ${sender} ${recipient}' >> /etc/postfix/master.cf


# By default, Dovecot has a bunch of example configs in `/usr/share/doc/dovecot/example-config/` These
# files have nice documentation if you want to read it, but it's a huge pain to go through them to organize.
# Instead, we simply use /etc/dovecot/dovecot.conf because it's easier to manage.

echo 'Generating a DH parameters file for Dovecot...'

mkdir -p /etc/dovecot
openssl dhparam -out /etc/dovecot/dh.pem 3072

echo 'Creating Dovecot config...'

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

protocols = \$protocols imap

# Search for valid users in /etc/passwd
userdb {
	driver = passwd
}

#Fallback: Use plain old PAM to find user passwords
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
		autoexpunge = 30d
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

# Here we let Postfix use Dovecot's authetication system.

service auth {
	unix_listener /var/spool/postfix/private/auth {
		mode = 0660
		user = postfix
		group = postfix
	}
}

protocol lda {
	mail_plugins = \$mail_plugins sieve
}

protocol lmtp {
	mail_plugins = \$mail_plugins sieve
}

plugin {
	sieve = ~/.dovecot.sieve
	sieve_default = /var/lib/dovecot/sieve/default.sieve
	sieve_dir = ~/.sieve
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

echo 'Preparing user authentication...'
grep -q nullok /etc/pam.d/dovecot ||
echo 'auth    required        pam_unix.so nullok
account required        pam_unix.so' >> /etc/pam.d/dovecot

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
opendkim-genkey -D /etc/postfix/dkim/ -d "$domain" -s "$subdom"

# Generate the OpenDKIM info:
echo 'Configuring OpenDKIM...'
grep -q "$domain" /etc/postfix/dkim/keytable 2>/dev/null ||
echo "$subdom._domainkey.$domain $domain:$subdom:/etc/postfix/dkim/$subdom.private" >> /etc/postfix/dkim/keytable

grep -q "$domain" /etc/postfix/dkim/signingtable 2>/dev/null ||
echo "*@$domain $subdom._domainkey.$domain" >> /etc/postfix/dkim/signingtable

grep -q '127.0.0.1' /etc/postfix/dkim/trustedhosts 2>/dev/null ||
echo '127.0.0.1' >> /etc/postfix/dkim/trustedhosts

# ...and source it from opendkim.conf
grep -q '^KeyTable' /etc/opendkim/opendkim.conf 2>/dev/null || echo "KeyTable file:/etc/postfix/dkim/keytable
SigningTable refile:/etc/postfix/dkim/signingtable
InternalHosts refile:/etc/postfix/dkim/trustedhosts
Domain $domain" >> /etc/opendkim/opendkim.conf

sed -i '/^#Canonicalization/s/simple/relaxed\/simple/' /etc/opendkim/opendkim.conf
sed -i '/^#Canonicalization/s/^#//' /etc/opendkim/opendkim.conf

sed -i '/Socket/s/^#*/#/' /etc/opendkim/opendkim.conf
grep -q '^Socket\s*inet:12301@localhost' /etc/opendkim/opendkim.conf || echo 'Socket inet:12301@localhost' >> /etc/opendkim/opendkim.conf

# Here we add to postconf the needed settings for working with OpenDKIM
echo 'Configuring Postfix with OpenDKIM settings...'
postconf -e 'smtpd_sasl_security_options = noanonymous, noplaintext'
postconf -e 'smtpd_sasl_tls_security_options = noanonymous'
postconf -e "myhostname = $maildomain"
postconf -e 'milter_default_action = accept'
postconf -e 'milter_protocol = 6'
postconf -e 'smtpd_milters = inet:localhost:12301'
postconf -e 'non_smtpd_milters = inet:localhost:12301'
postconf -e 'mailbox_command = /usr/lib/dovecot/deliver'

useradd -mG mail dmarc

systemctl enable --now spamassassin opendkim dovecot postfix

pval="$(tr -d "\n" </etc/postfix/dkim/$subdom.txt | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o "p=.*")"
dkimentry="$subdom._domainkey.$domain	TXT	v=DKIM1; k=rsa; $pval"
dmarcentry="_dmarc.$domain	TXT	v=DMARC1; p=reject; rua=mailto:dmarc@$domain; fo=1"
spfentry="$domain	TXT	v=spf1 mx a:$maildomain -all"

echo "$dkimentry
$dmarcentry
$spfentry" > "$HOME/dns_emailwizard"

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

$spfentry
\033[0m
NOTE: You may need to omit the \`.$domain\` portion at the beginning if
inputting them in a registrar's web interface.

Also, these are now saved to \033[34m~/dns_emailwizard\033[0m in case you want them in a file.

Once you do that, you're done! Check the README for how to add users/accounts
and how to log in.
"
