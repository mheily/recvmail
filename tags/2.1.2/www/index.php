<?php include "header.html"?>

<h2>Overview</h2>

Recvmail is a <a href="license.php">free</a> SMTP server that accepts messages from the Internet and delivers them to virtual mailboxes.  It's major design goals are simplicity, security, and efficiency.  
<p>
The name "recvmail" is pronounced <i>"receive mail"</i>, and has several meanings:
<ul>
<li>an obscure reference to the <a href="http://www.openbsd.org/cgi-bin/man.cgi?query=recv&apropos=0&sektion=0&manpath=OpenBSD+Current&arch=i386&format=html">recv(2)</a> system call
<li>a subtle reference to the <a href="http://sendmail.org">Sendmail</a> mailserver
<li>an obvious reference to the fact that it receives mail.
</ul>
<p>
<p>
The source code is available for <a href="download.php">download</a>.  Please note that Recvmail only accepts incoming mail and does not relay mail to other hosts. To have a complete bidirectional mail system, recvmail should be combined with another MTA such as <a href="http://sendmail.org">Sendmail</a>. In this configuration, sendmail is responsible for sending mail, while recvmail is responsible for receiving mail.

<h2>Current Status</h2>

The current stable version is <?php echo "$stable_version"?>.

<?php include "footer.html"?>
