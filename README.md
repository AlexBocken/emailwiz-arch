# emailwiz-arch

Set up a minimal email server on Arch Linux with a single script.
This script is largely based off of Luke's emailwiz for Debian: [emailwiz](https://github.com/LukeSmithxyz/emailwiz).

Small changes were made to the script to make it work on Arch Linux.

# NOTE

You need to fill the value of **$domain** as outlined in the script.

For more info read https://github.com/LukeSmithxyz/emailwiz/blob/master/README.md

## Spam auto-learning

The script wires up SpamAssassin Bayes auto-learning through Dovecot IMAPSieve
(filing into Junk learns spam, moving out learns ham). To enable it on a server
that was set up with an older version of the script, see
[docs/spam-autolearn.md](docs/spam-autolearn.md).

## Malware scanning

The script runs a ClamAV milter that scans mail during the SMTP transaction and
rejects infected messages before delivery. To enable it on a server that was set
up with an older version of the script, see
[docs/clamav-milter.md](docs/clamav-milter.md).
