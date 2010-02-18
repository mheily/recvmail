<?php include "header.html"?>

<h2>Installation</h2>

<h3>FreeBSD</h3>
<ol>
<li>$ ./configure && make</li>
<li>$ su</li>
<li># make install</li>
<li># pw group add recvmail</li>
<li># pw useradd -c 'recvmail daemon' -d /srv/mail -g recvmail -L daemon -s /bin/false -n recvmail</li>
<li># mkdir -p /srv/mail/spool/{new,cur,tmp}</li>
<li># mkdir -p /srv/mail/box/recvmail.org</li>
<li># chmod -R 700 /srv/mail</li>
<li># chown -R recvmail:recvmail /srv/mail</li>
</ol>

<?php include "footer.html"?>
