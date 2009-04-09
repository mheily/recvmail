<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<?php include "header.html"?>

<h2>Features</h2>




<h3>Anti-Spam</h3>
<ul>
<li><b>100% unprivileged</b><p>
</ul>

<h3>Security</h3>

<ul>

<li><b>100% unprivileged</b><p>

Unlike other mailers, recvmail doesn't require any root privileges. None. Zero.

<li><b>100% restricted to a chroot(2) jail</b><p>

The entire program runs inside of a chroot(2) jail.

</ul>

<h3>Simplicity</h3>

<ul>

<li><b>No configuration needed</b><p>

Mailservers are notoriously complex beasts that can be hard to set up and configure. Recvmail does not use a configuration file, and doesn't require any command line options. It is the easiest MTA you will ever use.

<li><b>Unidirectional</b><p>

Recvmail can receive mail, but not send it. Mail flows into the system from external hosts and is stored in one or more mailboxes. It is never forwarded, redirected, or bounced.  This makes the design of the server much simpler, and less error-prone.

<li><b>Direct delivery</b><p>

In the Recvmail system, mail is delivered directly to the destination mailbox and is not stored in a "queue". Most other programs store messages in a temporary directory, which increases the overall complexity of the system and decreases reliability. 

<li><b>Efficient use of disk storage</b><p>

When a sender specifys multiple mailboxes to receive a single message, Recvmail
stores a single copy of the message on the filesystem and creates multiple hard links.  This is more efficient than creating a unique copy of the message for every recipient. 

<li><b>Efficient memory requirements</b><p>

Recvmail uses streaming I/O instead of buffering the entire message. This means that 
after each line of input is received from the sender, it is written to disk. 
This approach minimizes the amount of memory required to process each message, 
and makes good use the operating systems buffer cache.

<li><b>Event-driven design</b><p>

Recvmail uses <a href="http://monkey.org/~provos/libevent/">libevent</a> to handle all client connections inside a single process. This is more efficient than using a dedicated thread for each client connection.

<li><b>Mail does not bounce</b><p>

If there are errors, they are reported to the sender during the SMTP conversation. Traditionally, the sender would hang up, and errors would be returned using a "bounce message". For various reasons, Recvmail does not exhibit this behaviour.

<li><b>Privileges are revoked</b><p>

As soon as possible, Recvmail permanently and completely drops root privileges, and the entire process is restricted to a chroot(2) jail. Most other software is designed to have one privileged component that interfaces with other non-privileged components. Since Recvmail uses virtual accounts, there is no need for it to have access to the system accounts.

<li><b>System calls are restricted by systrace(1)</b><p>

By default, Recvmail runs under the <a href="http://www.citi.umich.edu/u/provos/systrace/">systrace</a> mechanism, which limits the type of system calls available to the program. In particular, the Recvmail daemon is not allowed to connect to other systems, open files for reading, delete files, or execute programs. Click <a href="systrace.policy">here</a> to view the systrace policy.

<li><b>DNS lookups are not done</b><p>

Most mailservers issue a reverse DNS query every time a new client connects; Recvmail does not. With the large volume of mail traffic, most of which coming from compromised "zombie" machines operated by spammers, this DNS lookup is a pointless waste of resources. 

<!-- TODO
<li><b>Source code is peer reviewed</b><p>

Most other mailservers are huge programs that would take a long time to review the source code.  Because of it's small size and simple design, Recvmail was
designed to be reviewed.
<p>

Software is only "secure" after it has been throughly tested and peer reviewed. Since Recvmail is brand new, it has not undergone this process. If you are a security researcher, or someone with experience spotting security flaws in C programs, and would like to participate in the review, please visit the <a href="security.html#peer-review">security audit<a> page.
-->

<li><b>Clean design</b><p>

Instead of providing many options and features, Recvmail tries to choose the best way to do things and then does it. For example, it uses Maildirs
instead of mbox; it uses virtual accounts instead of system accounts.

<li><b>Virtual accounts</b><p>

Instead of delivering to mailboxes for system accounts, Recvmail is a purely virtual server. There is no association between system accounts and mailboxes.

<li><b>Clustering</b><p>

Recvmail was designed from the very beginning to support clustering, which allows multiple "front end" servers to deliver mail to a single "back end" mailstore.

</ul>

<?php include "footer.html"?>
