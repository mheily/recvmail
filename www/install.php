<?php include "header.html"?>

<h2>Installation</h2>

<h3>FreeBSD</h3>
<ol>
<li>./configure && make && sudo make install</li>
<li>sudo pw group add recvmail</li>
<li>sudo pw useradd -c 'recvmail daemon' -d /srv/mail -g recvmail -L daemon -s /bin/false -m -n recvmail</li>
</ol>

<?php include "footer.html"?>
