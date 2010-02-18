<?php include "header.html"?>

<h2>Installation</h2>

<h3>FreeBSD</h3>
<ol>
<li>./configure && make && sudo make install</li>
<li>su</li>
<li># sudo pw group add recvmail</li>
<li># sudo pw useradd -c 'recvmail daemon' -d /srv/mail -g recvmail -L daemon -s /bin/false -m -n recvmail</li>
<li># chmod 700 /srv/mail</li>
<li># sudo -u recvmail mkdir -p /srv/mail/spool/{new,cur,tmp}</li>
<li># sudo -u recvmail mkdir -p /srv/mail/box/recvmail.org</li>
</ol>

<?php include "footer.html"?>
