# Debian #

  1. Install the Dovecot IMAP server.
```
# apt-get install dovecot-imapd
```
  1. Edit `/etc/dovecot/dovecot.conf`
    1. Set the mail\_location to the virtual user's home directory.
```
mail_location = maildir:/srv/mail/box/%d/%n
```
    1. Configure the authentication mechanism.
```
auth default {
  mechanisms = plain
  passdb passwd-file {
    args = /etc/dovecot/passwd
  }
  userdb static {
    args = uid=recvmail gid=recvmail home=/srv/mail/box/%d/%n
  }
}
```
  1. Edit the password file named `/etc/dovecot/passwd` and add user accounts.
```
john.doe@recvmail.org:{PLAIN}secret
```
  1. Restart Dovecot
```
# /etc/init.d/dovecot restart
```