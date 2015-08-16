#!/usr/bin/env perl
use Net::SMTP;
chomp($mailhost=`hostname`);
$smtp = Net::SMTP->new($mailhost, Debug => 1);
$smtp->mail($ENV{USER});
if ($smtp->to('test@' . $mailhost)) {
     $smtp->data();
     $smtp->datasend("To: test\@" . $mailhost ."\n");
     $smtp->datasend("\n");
     $smtp->datasend("A simple test message\n");
     $smtp->dataend();
    } else {
     print "Error: ", $smtp->message();
    }
$smtp->quit;
