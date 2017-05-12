#!/usr/bin/perl


# Copyright (c) 2001-2003, Firma PAF
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of Firma PAF nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use Getopt::Std;
use Net::DNS;
use IO::Socket;
use IO::Select;
use Fcntl ':flock';
use IO::Handle;

use Apply;

do "settings.pl";

my %settings = %settings::settings;
my @argv = @settings::argv;

my $global_cache;
my %ok_email;
my @log_msg;
my %options;
my %checked_zone;
my $level;
my %verified_a;
my %verified_ptr;
my $thedatestring;

# Defaults
my $global_loglevel;
my $global_timeout;
my $global_retrans;
my $global_retry;
my $global_check_parent;
my $global_check_children;
my $global_logfile;
my $global_children;
my $global_log;
my $global_maxtries;
my $router;
my $username;


$log_msg[5] = "DNS";
$log_msg[4] = "DEBUG";
$log_msg[3] = "INFO";
$log_msg[2] = "WARNING";
$log_msg[1] = "ERROR";

sub new_resolver {
    my $r = new Net::DNS::Resolver;
    $r->retrans($global_retrans);
    $r->retry($global_retry);
    $r->tcp_timeout($global_timeout);
    $r->dnsrch(0);
    return $r;
}

sub do_log {
    my $zone = $_[0];
    my $owner = $_[1];
    my $loglevel = $_[2];
    my $logtext = $_[3];
    my $errorval = $_[4];
    my $errortxt = $_[5];

    if($loglevel > $global_loglevel) {
	return;
    }
    if(length($zone) == 0) {
	$zone = ".";
    }
    if(length($errortxt) > 0) {
	$errortxt = " ($errortxt)";
    } else {
	$errortxt = "";
    }
    $global_log->autoflush(1);
    flock($global_log,LOCK_EX);
    seek($global_log, 0, 2);
    print $global_log "$zone:$thedatestring:$log_msg[$loglevel]:$errorval:$owner:$logtext$errortxt\n";
    flock($global_log,LOCK_UN);
};

sub rrstring {
    my($r) = @_;
    my $s = "";

    my $s = $r->name . ". " . $r->ttl . " " . $r->class . " " . $r->type . " ";

    if($r->type eq "SOA") {
	$s = $s . $r->mname . ". ";
	$s = $s . $r->rname . ". ";
	$s = $s . $r->serial . " ";
	$s = $s . $r->refresh . " ";
	$s = $s . $r->retry . " ";
	$s = $s . $r->expire . " ";
	$s = $s . $r->minimum;
    } else {
	$s = $s . $r->rdatastr;
    }
    return($s);
}

sub settime {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime(time);
    my $str = sprintf("%04d%02d%02d-%02d.%02d.%02d",$year + 1900,$mon + 1,$mday,$hour,$min,$sec);
    $thedatestring = $str;
};

sub ip2as {
    my($ip,$zone) = @_;

    do_log($zone,"",5,"Query $router. IN A",135);

    my $s = IO::Socket::INET->new(PeerAddr => $router,
				   PeerPort => 23,
				   Proto    => "tcp",
				   Type     => SOCK_STREAM,
				   Timeout  => 60);

    if(!$s) {
	do_log($zone,"",3,"Could not check AS number for IP address ${ip}",50);
	goto ERROR;
    }

    $/ = ":";
    $_ = <$s>;
    print $s "$username\n";
    $/ = ">";
    $_ = <$s>;
    print $s "show ip bgp $ip\n";
    my $msg = <$s>;
    print $s "exit\n";
    close($s);

    $/ = "\n";
    my @lines = split(/\n/,$msg);
    my @res;
    my $as;
    @res = grep {/^  [ 0-9][ 0-9]*,/} @lines;
    my $line;
    foreach $line (@res) {
	$line =~ s/^.* ([0-9]*),.*$/$1/;
	if(length($as) == 0) {
	    do_log($zone,"",4,"IP address ${ip} announced by AS ${line}",51);
	    $as = $line;
	} else {
	    if($as != $line) {
		do_log($zone,"",2,"IP address ${ip} announced not only by AS ${as}, but also by AS ${line}",31);
	    }
	}
    }
    @res = grep {/Local/} @lines;
    foreach $line (@res) {
	$as = $line;
    }
    return($as);
ERROR:
    return("unknown");
}

sub same_list {
    my ($a, $b) = @_;

    my $aa = lc(join(':',sort(@$a)));
    my $bb = lc(join(':',sort(@$b)));
    my $str;
    if($bb eq "") {
	foreach $str (@$a) {
	    push @$b, $str;
	}
	$bb = join(':',sort(@$b));
    }
    if($aa eq $bb) {
	return 1;
    }
    return 0;
};

sub verify_a {
    my ($host,$cnameok,$zone,$level,$errorlevel) = @_;

    if($level > 10) {
	do_log($zone,"",1,"Too deep recursion in A/CNAME/PTR chain for name ${host}",19);
	return;
    }
    $level++;
    do_log($zone,"",4,"Level of recursion for $host is now $level (A)",52);

    my $r;

    # Check that we have A record for this NS
    if($verified_a{lc($host)} > 0) {
	do_log($zone,"",4,"We have already checked $host",53);
	return;
    }

    $verified_a{lc($host)} = 1;
    unless(defined($errorlevel)) {
	$errorlevel = 1;
    }
    do_log($zone,"",4,"Fetching A for ${host}",54);
    my $ress = new_resolver;
    do_log($zone,"",5,"Query $host. IN A",135);
    my $packet = $ress->query($host . ".","A");
    if(!$packet) {
	do_log($zone,"",$errorlevel,"No A record found for ${host}",1);
	$verified_a{lc($host)} = -1;
	return;
    };
    foreach $r ($packet->answer) {
	do_log($zone,"",5,"Response " . rrstring($r),136);
    }
    do_log($zone,"",4,"Got " . $packet->header->ancount . " records back",128);
    foreach $r ($packet->answer) {
	if($r->type eq "A") {
	    $verified_a{lc($host)} = 2;
	    do_log($zone,"",3,"${host} has A " . $r->address,55);
	    verify_ptr($r->address,1,$zone,$level,$errorlevel);
	} elsif ($r->type eq "CNAME") {
	    do_log($zone,"",3,"${host} has CNAME " . $r->cname,56);
	    if(!$cnameok) {
		do_log($zone,"",1,"${host} has illegal CNAME " . $r->cname,15);
		$verified_a{lc($host)} = -1;
	    } else {
		$verified_a{lc($host)} = 2;
		verify_a($r->cname,0,$zone,$level,$errorlevel);
	    };
	} else {
	    do_log($zone,"",2,"${host} has " . r->type . " record found",20);
	}
    }
    return;
};


sub verify_ptr {
    my ($host,$cnameok,$zone,$level) = @_;

    if($level > 10) {
	do_log($zone,"",1,"Too deep recursion in A/CNAME/PTR chain for name ${host}",19);
	return(1);
    }
    $level++;
    do_log($zone,"",4,"Level of recursion for $host is now $level",52);

    my $r;

    # Check that we have PTR record for this address
    if($verified_ptr{lc($host)} > 0) {
	do_log($zone,"",4,"Already checking PTR for $host",58);
	return;
    };

    $verified_ptr{lc($host)} = 1;

    do_log($zone,"",4,"Fetching PTR for ${host}",59);
    do_log($zone,"",5,"Query $host IN PTR",135);
    my $ress = new_resolver;
    my $packet = $ress->query($host,"PTR");
    if(!$packet) {
	do_log($zone,"",2,"No PTR record found for ${host}",2);
	$verified_ptr{lc($host)} = -1;
	return;
    };
    foreach $r ($packet->answer) {
	do_log($zone,"",5,"Response " . rrstring($r),136);
    }
    do_log($zone,"",4,"Got " . $packet->header->ancount . " records back",128);
    foreach $r ($packet->answer) {
	if($r->type eq "PTR") {
	    $verified_ptr{lc($host)} = 2;
	    do_log($zone,"",3,"${host} has PTR " . $r->ptrdname,60);
	    verify_a($r->ptrdname,$cnameok,$zone,0,2);
	} elsif ($r->type eq "CNAME") {
	    $num++;
	    do_log($zone,"",3,"${host} has CNAME " . $r->cname,61);
	    if(!$cnameok) {
		do_log($zone,"",1,"${host} has illegal CNAME " . $r->cname,17);
		$verified_ptr{lc($host)} = -1;
	    } else {
		$verified_ptr{lc($host)} = 2;
		verify_ptr($r->cname,0,$zone,$level);
	    };
	} else {
	    do_log($zone,"",2,"${host} has " . r->type . " record found",21);
	}
    };
    return;
};


sub write_msg {
    my ($socket, $msg, $timeout, $dmsg,$zone) = @_;

    $socket->blocking(0);
    my $sel = new IO::Select($socket);

    $msg = $msg . "\015\012";
    my $offset = 0;
    my $len = length($msg);
    my @ready;
    my $written;

    while($len) {
	@ready = $sel->can_write(5);
	if(!@ready) {
	    do_log($zone,$dmsg,4,"Timeout when waiting for socket for writing",62);
	    return 0;
	}
	$written = syswrite($socket, $msg, $len, $offset);
	if($written == undef) {
	    do_log($zone,$dmsg,4,"Error when writing to socket: $!",63);
	    return 0;
	}
	$offset += $written;
	$len -= $written;
    }
    chop $msg;
    chop $msg;
    do_log($zone,$dmsg,4,"> $msg",64);
    return 1;
}


sub read_msg {
    my ($socket, $timeout, $dmsg, $zone) = @_;

    $socket->blocking(0);
    my $sel = new IO::Select($socket);

    my $msg = "";
    my $separator = "-";
    my $line;

    while($separator eq "-") {
	my @ready = $sel->can_read($timeout);
	if(!@ready) {
	    do_log($zone,$dmsg,4,"Timeout when waiting for socket for reading",65);
	    return undef;
	}
	my $nread = sysread($socket,$msg,1024);
	if($nread == undef) {
	    do_log($zone,$dmsg,4,"Error when reading from socket: $!",66);
	    return undef;
	}

	$msg =~ s/\015\012/!/g;
	my @lines = split('!',$msg);
	foreach $line (@lines) {
	    do_log($zone,$dmsg,4,"< $line",67);
	    $line=~s/^[0-9][0-9][0-9]([ -]).*$/\1/;
	    $separator=$line;
	}
    }

    $msg =~ s/^([0-9][0-9][0-9]).*$/\1/;
    return $msg;
}


sub smtp_msg {
    my($s,$msg,$dmsg,$zone) = @_;

    if(length($msg) > 0) {
	write_msg($s,$msg,$global_timeout,$dmsg,$zone) or return 0;
    }

    my $response = read_msg($s,$global_timeout,$dmsg,$zone) or return 0;

    if(substr($response,0,1)!="2") {
	do_log($zone,$dmsg,4,"Not accepted: ${msg}",68);
	return 0;
    }
    return 1;
}

sub check_mail {
    my ($ip, $address, $zone) = @_;

    my $res;

    $level=0;
    verify_a($ip,0,$zone,0,1);

    do_log($zone,"",5,"Query $ip IN A",135);

    my $s = IO::Socket::INET->new(PeerAddr => $ip,
			       PeerPort => 25,
			       Proto    => "tcp",
			       Type     => SOCK_STREAM,
			       Timeout  => $global_timeout);
    if(!$s) {
	do_log($zone,$ip,2,"Could not open connection to ${ip}:25",25);
	goto ERROR;
    }

    if($debuglevel > 4) {
	my ($a,$b,$c,$d) = unpack('C4',$s->sockaddr);
	do_log($zone,"",5,"Query $d.$c.$b.$a.in-addr.arpa. IN PTR",135);
    }
    my $myhostname = gethostbyaddr($s->sockaddr,&AF_INET);

    smtp_msg($s,"",$ip,$zone) or goto ERROR;

    my $hello = "EHLO";
  HELLO:
    $res = smtp_msg($s,$hello . " $myhostname",$ip,$zone);
    if(!$res) {
	if($hello eq "EHLO") {
	    do_log($zone,$ip,3,"Server does not support $hello",69);
	    smtp_msg($s,"RSET",$ip,$zone) or goto ERROR;
	    $hello = "HELO";
	    goto HELLO;
	} else {
	    do_log($zone,$ip,2,"Server does not support RSET after EHLO",29);
	    goto ERROR;
	}
    }

    my $mail_from = "<>";
  FROM:
    my $result = smtp_msg($s,"MAIL FROM: " . $mail_from,$ip,$zone);
    if(!$result) {
	if($mail_from eq "<>") {
	    do_log($zone,$ip,2,"Server does not accept empty envelope from",22);
	    smtp_msg($s,"RSET",$ip,$zone) or goto ERROR;
	    $mail_from = "<" . $settings{myemailaddr} . ">";
	    goto FROM;
	} else {
	    goto ERROR;
	}
    }

    smtp_msg($s,"RCPT TO: <" . $address . ">",$ip,$zone) or goto ERROR;

    my $r = 1;
    goto QUIT;

  ERROR:
    $r = 0;
    do_log($zone,$ip,4,"Closing socket",70);
    close($s);
    $s = 0;

  QUIT:
    if($s) {
	do_log($zone,$ip,4,"Trying to send a QUIT message",71);
	smtp_msg($s,"QUIT",$ip,$zone) or return 0;
	do_log($zone,$ip,4,"Closing socket",72);
	close($s);
    }

    my $ok;
    my $code;
    my $num;
    if($r) {
	$ok = "ok";
	$code = "3";
	$num = "73";
    } else {
	$ok = "not ok";
	$code = 2;
	$num = "32";
    }
    do_log($zone,$ip,$code,"$address $ok at $ip",$num);

    return($r);
};

sub checkmail {
    my ($mailaddress,$zone) = @_;
    do_log($zone,"",4,"Testing $mailaddress",74);

    my $domain = $mailaddress;
    $domain =~ s/^.*@//;

    do_log($zone,"",4,"Looking for MX for domain $domain",75);

    my $res = new_resolver;

    my @mxhosts;

    undef @mxhosts;

    do_log($zone,"",5,"Query $domain. IN MX",135);
    my $packet = $res->send($domain . ".","MX");
    my $r;

    if($packet) {
	foreach $r ($packet->answer) {
	    do_log($zone,"",5,"Response " . rrstring($r),136);
	}
	foreach $r ($packet->answer) {
	    if($r->type eq "MX") {
		do_log($zone,"",4,"$domain IN MX " . $r->preference . " " . $r->exchange,76);
		push(@mxhosts, $r->exchange);
	    }
	}
    }
    if(scalar(@mxhosts) == 0) {
	do_log($zone,"",4,"No MX found...lets use $domain and A",77);
	push(@mxhosts, $domain);
    }
    my $found = 0;
    my $error = 0;
    my $mxhost;
    my $result;
    foreach $mxhost (@mxhosts) {
	do_log($zone,$mxhost,3,"Testing mail to $mailaddress at $mxhost",78);
	$result = check_mail($mxhost, $mailaddress,$zone);
	if($result) {
	    $found = 1;
	} else {
	    $error = 1;
	}
    }
    if($found && !$error) {
	return 2;
    } elsif ($found && $error) {
	return 1;
    } else {
	return 0;
    }
}

sub check_glue {
    my ($zone, $thens, $ns, $glue) = @_;

    # Create a regexp which matches $zone
    my $nzone = "$zone\$";
    $nzone =~ s/\./\\./g;

    $res = new_resolver;

    my @theglue;

    foreach $nameserver (@$ns) {
	undef @theglue;
	if($nameserver =~ /$nzone/i) {
	    do_log($zone,$thens,4,"Checking glue for " . $nameserver,113);
	    my $num = 0;
	    $res->nameservers($thens);
	    my $loop = 0;
RETRY:
	    $loop++;
	    if($loop > 10) {
		do_log($zone,$thens,1,"Loop in glue record chain",132);
		return;
	    }
	    do_log($zone,join(",",$res->nameservers),5,"Query $nameserver. IN A",135);
	    my $packet = $res->send($nameserver . ".","A");
	    my @records;
	    if($packet) {
		if($packet->header->ancount > 0) {
		    do_log($zone,$thens,4,"Found data in answer section",130);
		    @records=$packet->answer;
		} elsif ($packet->header->arcount > 0) {
		    do_log($zone,$thens,4,"Found data in answer section",131);
		    @records=$packet->additional;
		}
		foreach $record(@records) {
		    do_log($zone,join(",",$res->nameservers),5,"Response " . rrstring($record),136);
		}
		foreach $record(@records) {
		    if($record->type eq "CNAME") {
			if(lc($record->name) eq $nameserver) {
			    $nameserver = $record->cname;
			    do_log($zone,$thens,4,"Found CNAME, switching to look for $nameserver",134);
			} else {
			    do_log($zone,$thens,4,"Found CNAME which doesn't match $nameserver",133);
			}
			next;
		    }
		    unless ($record->type eq "A") {
			do_log($zone,$thens,4,"Found rr of type " . $record->type,132);
			next;
		    }
		    unless (lc($record->name) eq $nameserver) {
			do_log($zone,$thens,4,"Found record which doesn't match " . $record->name,132);
			next;
		    }
		    do_log($zone,$thens,3,"Found glue " . $record->address . " for " . $record->name,120);
		    push @theglue, $record->address;
		    $num++;
		}
		if($num == 0) {
		    if($packet->header->nscount > 0) {
			my @auth = $packet->authority;
			my $number = 0;
			do_log($zone,$thens,4,"Got authority information",121);
			foreach $authrecord(@auth) {
			    my $match = $authrecord->name;
			    if($authrecord->type eq "NS" && length($authrecord->name) > 0 && $nameserver =~ /$match/) {
				push @tmpns, $authrecord->nsdname;
				do_log($zone,$thens,4,"Adding " . $authrecord->nsdname . " to list of nameservers to query",122);
				$number++;
			    }
			}
			if($number>0) {
			    $res->nameservers(@tmpns);
			    do_log($zone,$thens,4,"Restarting query for $nameserver",123);
			    goto RETRY;
			}
		    }
		}
	    }
	    if($num > 0) {
		$g = join(':',sort(@theglue));
		if(defined($glue->{$nameserver})) {
		    if($glue->{$nameserver} ne $g) {
			do_log($zone,$thens,1,"Glue is different " . $glue->{$nameserver} . " and " . $g . " for $nameserver", 34);
		    } else{
			do_log($zone,$thens,3,"Glue is same " . $glue->{$nameserver} . " and " . $g . " for $nameserver", 137);
		    }
		} else {
		    $glue->{$nameserver} = $g;
		    do_log($zone,$thens,3,"Saving glue " . $glue->{$nameserver} . " for " . $nameserver, 138);
		}
	    } else {
		do_log($zone,$thens,1,"Didn't get any glue for $nameserver",119);
	    }
	}
    }
}


sub check_one_zone {
    my $local_cache;
    my ($zone,$checkparent) = @_;
    my $res;
    my $rr;
    my $query;
    my @parent_ns;
    my @my_ns;
    my %parent_zone;
    my %glue;
    my $saved_email_address;
    my $saved_master;
						     
    settime;

    $zone =~ s/\.$//;

    do_log($zone,"",3,"Start check",79);

    if(length($zone) == 0) {
	do_log($zone,"",1,"Checking root zone doesn't make any sense",122);
	do_log($zone,"",3,"Ready with this zone",106);
	return(0);
    }

    my @saved_ns;
    undef @saved_ns;

    # Check statically configured nameservers for zone
    if(length($settings{dnsservers}) > 0) {
	do_log($zone,"",4,"Using DNS servers in settings " . $settings{dnsservers},116);
	# We have explicit DNS servers to query
	# Do NOT check parent servers at all
	my @servers=split(/,/,$settings{dnsservers});
	foreach $i (0..$#servers) {
	    do_log($zone,"",4,"Requested to use " . $servers[$i] . " as nameserver",114);
	    unless($servers[$i] =~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
		do_log($zone,"",5,"Query " . $servers[$i] . " IN A",135);
		my ($name,$aliases,$addrtype,$length,@addrs) = gethostbyname($servers[$i]);
		do_log($zone,"",4,"Found " . ($#addrs+1) . " IP address(es) for " . $servers[$i], 115);
		if($#addrs < 0) {
		   do_log($zone,"",1,"Can not find IP address for " . $servers[$i], 11);
	        }
		foreach $i (@addrs) {
		    my ($a,$b,$c,$d) = unpack('C4',$i);
		    push @saved_ns, "$a.$b.$c.$d";
		    do_log($zone,"",5,"Response " . $servers[$i] . " IN PTR $a.$b.$c.$d",136);
		}
	    } else {
		push @saved_ns,$servers[$i];
	    }
	}
	$res = new_resolver;
	$res->recurse(0);

	goto HAVENAMESERVERS;
    }

    # Calculate what the name of the parent zone is
    my $parentzone = $zone;

    $res = new_resolver;

    do {
	# Set $1 to string after first .
	$_ = $parentzone;
	if(/^[^.]*$/) { # No periods at all in name
	    $parentzone = ".";
	} else {
	    $parentzone =~ s/^[^.]*\.//;
	}
	
	# Fetch NS records for parent domain of zone
	do_log($zone,"",4,"Fetching NS for parent zone ${parentzone}",80);
	my $res = new_resolver;
	if($parentzone eq ".") {
	    do_log($zone,"",5,"Query $parentzone IN NS",135);
	    $query = $res->query($parentzone,"NS");
	} else {
	    do_log($zone,"",5,"Query $parentzone. IN NS",135);
	    $query = $res->query($parentzone . ".","NS");
	}
	if ($query) {
	    foreach $rr ($query->answer) {
		do_log($zone,"",5,"Response " . rrstring($rr),136);
	    }
	    foreach $rr ($query->answer) {
		next unless $rr->type eq "NS";
		do_log($zone,"",3,"Found NS " . $rr->nsdname . " for parent ${parentzone}",81);
		push(@parent_ns, $rr);
	    }
	}
	else {
	    do_log($zone,"",4,"NS for parent zone ${parentzone} not found (" . $res->errorstring . ")",82);
	    if($res->errorstring eq "query timed out" && $parentzone eq ".") {
		do_log($zone,"",4,"Exiting because NS for root zone do exist",83);
		do_log($zone,"",3,"Ready with this zone",106);
		return(1);
	    }
	}
    } until $query or $parentzone eq ".";

    # Turn off recursion
    $res->recurse(0);
    my $ns;
    my @ns;
    my $packet;
    my @found_ns;
    my @saved_soa;
    # Loop over the parent NS records
  PARENT:
    while(defined($ns = pop(@parent_ns))) {
	do_log($zone,$ns->nsdname,4,"Checking records",84);
	# Set the nameserver to query this specific parent one
	$res->nameservers($ns->nsdname);
	
	# Collect NS records for zone from this parent zone
	undef @ns;
	undef %parent_zone;
	
	do_log($zone,$ns->nsdname,4,"Fetching NS from parent",85);
	do_log($zone,$ns->nsdname,5,"Query $zone. IN NS",135);
	$packet = $res->send($zone . ".","NS");
	if ($packet) {
	    if($packet->header->ancount > 0) {
		@found_ns = $packet->answer;
		do_log($zone,$ns->nsdname,4,"Found record in answer section",86);
	    } elsif($packet->header->nscount > 0) {
		do_log($zone,$ns->nsdname,4,"Found records in authority section",87);
		@found_ns = $packet->authority;
	    } else {
		do_log($zone,$ns->nsdname,1,"No NS found",4);
	    }
	    foreach $rr (@found_ns) {
		do_log($zone,$ns->nsdname,5,"Response " . rrstring($rr),136);
	    }
	    foreach $rr (@found_ns) {
		next unless $rr->type eq "NS";
		do_log($zone,$ns->nsdname,3,"${zone} IN NS " . $rr->nsdname,88);
		push(@ns, lc($rr->nsdname));
		$parent_zone{lc($rr->nsdname)} = 1;
	    }
	} else {
	    do_log($zone,"",4,"Some error with NS for $zone at " . $ns->nsdname . " (" . $res->errorstring . ")",89);
	    if($res->errorstring eq "query timed out") {
		do_log($zone,"",4,"Exiting because of timeout",90);
		do_log($zone,"",3,"Ready with this zone",106);
		return(1);
	    }
	}
	# Check that the NS are the same
	if(!same_list(\@ns,\@saved_ns)) {
	    do_log($zone,$ns->nsdname,1,"Inconsistent NS at parent servers",5,$ns->nsdname);
	}
      
	check_glue($zone,$ns->nsdname,\@ns,\%glue);

	if(scalar(@ns) == 0) {
	    do_log($zone,$ns->nsdname,1,"NS not found",6,$res->errorstring);
	} else {
	    if(!$checkparent) {
		do_log($zone,$ns->nsdname,4,"Got data we want",91);
		last PARENT;
	    };
	};

	# Collect SOA records for parent zone from parent zone
	my @soa;
	undef @soa;
	do_log($zone,$ns->nsdname,4,"Fetching SOA for parent zone ${parentzone}",92);
	if($parentzone eq ".") {
	    do_log($zone,$ns->nsdname,5,"Query $parentzone IN SOA",135);
	    $query = $res->query($parentzone,"SOA");
	} else {
	    do_log($zone,$ns->nsdname,5,"Query $parentzone. IN SOA",135);
	    $query = $res->query($parentzone . ".","SOA");
	}
	if ($query) {
	    foreach $rr ($query->answer) {
		do_log($zone,$ns->nsdname,5,"Response " . rrstring($rr),136);
	    }
	    foreach $rr ($query->answer) {
		next unless $rr->type eq "SOA";
		do_log($zone,$ns->nsdname,4,"SOA for ${parentzone} with serial " . $rr->serial,93);
		push(@soa, $rr->serial);
	    }
	} else {
	    if($res->errorstring eq "query timed out") {
		do_log($zone,"",4,"Exiting because of timeout",94);
		do_log($zone,"",3,"Ready with this zone",106);
		return(1);
	    }
	    do_log($zone,$parentzone,1,"SOA for ${parentzone} not found",7,$res->errorstring);
	}
	# Check that the serial numbers in the SOA are the same
	if(!same_list(\@soa,\@saved_soa)) {
	    do_log($zone,$ns->nsdname,2,"Inconsistent serial in SOA for ${parentzone} at parent servers",27,join(", ",@soa,@saved_soa));
	}
    }

HAVENAMESERVERS:

    # Loop over the NS records for zone
    my $num = 0;
    my $str;
    my @zone_ns;
    foreach $str (@saved_ns) {
	push @zone_ns, $str;
	$num++;
    }
    if($num < 2) {
	do_log($zone,"",1,"Too few NS records (${num}) for zone ${zone}",9);
    } else {
	do_log($zone,"",4,"Found ${num} NS records for zone ${zone} in parent zone",95);
    }
    undef @saved_soa;
    my %saved_as;
    undef %saved_as;

    my $some_auth = 0;

    #############################################
    # Here is the real checking, once for each NS
    # Loop over the NS records
    while(defined($ns = pop(@zone_ns))) {
	do_log($zone,$ns,4,"Checking records at $ns",96);

	unless($str =~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
	    do_log($zone,"",5,"Query $ns. IN A",135);
	    my ($name,$aliases,$addrtype,$length,@addrs) = gethostbyname($ns);
	    my $ad;
	    for $ad (@addrs) {
		my ($a,$b,$c,$d) = unpack('C4',$ad);
		do_log($zone,"",5,"Response $ns IN A $a.$b.$c.$d",136);
		if($settings{bgprouter}) {
		    my $as = ip2as("$a.$b.$c.$d",$zone);
		    $saved_as{$as} = 1;
		}
	    }
	} else {
	    if($settings{bgprouter}) {
		my $as = ip2as($ns,$zone);
		$saved_as{$as} = 1;
	    }
	}

	# Set the nameserver to query this specific one
	$res->nameservers($ns);

	$level=0;
	if($ns =~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
	    verify_ptr($ns,0,$zone,0);
	} else {
	    verify_a($ns,0,$zone,0,1);
	}

	# Collect NS records for zone from this server
	undef @ns;
	do_log($zone,$ns,4,"Fetching NS for $zone",97);
	do_log($zone,$ns,5,"Query $zone. IN NS",135);
	$packet = $res->send($zone . ".","NS");
	if ($packet && $packet->header->ancount > 0) {
	    foreach $rr ($packet->answer) {
		do_log($zone,$ns,5,"Response " . rrstring($rr),136);
	    }
	    if(!$packet->header->aa) {
		do_log($zone,$ns,1,"No Authoritative response on NS for ${zone}",10);
	    } else {
		$some_auth++;
	    }
	    foreach $rr ($packet->answer) {
		next unless $rr->type eq "NS";
		do_log($zone,$ns,3,"${zone} IN NS " . $rr->nsdname,98);

		# Check that this NS exists in parent zone
		if(defined($parent_zone)) {
		    if(!$parent_zone{lc($rr->nsdname)}) {
			do_log($zone,$ns,2,"Nameserver " . $rr->nsdname . " does not exist in parent zone but at ${ns}",28);
			push(@zone_ns,$rr->nsdname);
			$parent_zone{lc($rr->nsdname)} = 1;
			$level=1;
			verify_a($rr->nsdname,0,$zone,0,1);
		    }
		}

		push(@ns, lc($rr->nsdname));
	    }
	}
	else {
	    do_log($zone,$ns,1,"NS not found for ${zone} at ${ns}",12,$res->errorstring);
	}

	# Check glue records
	check_glue($zone,$ns,\@ns,\%glue);

        # Collect SOA records for zone
	my @soa;
	undef @soa;
	do_log($zone,$ns,4,"Fetching SOA for ${zone}",99);

	do_log($zone,$ns,4,"Use TCP",116);
	$res->usevc(1);
	do_log($zone,$ns,5,"Query $zone. IN SOA (over TCP)",135);
	$query = $res->query($zone . ".","SOA");
	if ($query) {
	    # This is stupid as we should only get one answer...but who knows
	    foreach $rr ($query->answer) {
		do_log($zone,$ns,5,"Response " . rrstring($rr),136);
	    }
	    foreach $rr ($query->answer) {
		next unless $rr->type eq "SOA";
		do_log($zone,$ns,3,"Found SOA over TCP for ${zone} with serial " . $rr->serial,100);
		if(!$query->header->aa) {
		    do_log($zone,$ns,1,"Non-authoritative response for SOA over TCP for ${zone} at server ${ns}",13,"");
		}
	    }
	} else {
	    do_log($zone,$ns,1,"Did not get SOA when using TCP",118);
	}
	$res->usevc(0);
	do_log($zone,$ns,4,"Use UDP",117);
	do_log($zone,$ns,5,"Query $zone. IN SOA",135);
	$query = $res->query($zone . ".","SOA");
	if ($query) {
	    # This is stupid as we should only get one answer...but who knows
	    foreach $rr ($query->answer) {
		do_log($zone,$ns,5,"Response " . rrstring($rr),136);
	    }
	    foreach $rr ($query->answer) {
		next unless $rr->type eq "SOA";
		do_log($zone,$ns,3,"Found SOA for ${zone} with serial " . $rr->serial,100);
		if(!$query->header->aa) {
		    do_log($zone,$ns,1,"Non-authoritative response for SOA for ${zone} at server ${ns}",13,"");
		}

		if(!$verified_a{$rr->mname}) {
		    do_log($zone,$ns,4,"Verifying A record for host in SOA",101);
		    $level=1;
		    verify_a($rr->mname,0,$zone,0,2);
		}
		$saved_master=lc($rr->mname);
		my $mailaddr = $rr->rname;
		do_log($zone,$ns,4,"Rname in SOA is ${mailaddr}",102);
		$mailaddr =~ s/(?<!\\)\./@/;
		$mailaddr =~ s/\\\././g;
		do_log($zone,$ns,4,"Email address is ${mailaddr}",103);
		$saved_email_address=lc($mailaddr);
		if($settings{smtp}) {
		    if(!$ok_email{lc($mailaddr)}) {
			my $result = checkmail($mailaddr,$zone);

			if($result == 0) {
			    do_log($zone,$ns,1,"$mailaddr found in SOA is not ok",14);
			} elsif ($result == 1) {
			    do_log($zone,$ns,2,"$mailaddr found in SOA works, but have non-working MX records",23);
			} else {
			    do_log($zone,$ns,3,"$mailaddr found in SOA is ok",104);
			    $ok_email{lc($mailaddr)} = 1;
			}
		    } else {
			do_log($zone,$ns,3,"$mailaddr found in SOA is ok",104);
		    }
		}

		push(@soa, $rr->serial);
		# Check that the serial numbers in the SOA are the same
		if(!same_list(\@soa,\@saved_soa)) {
		    do_log($zone,$ns,2,"Inconsistent serial in SOA for ${zone} at servers",24,join(", ",@soa,@saved_soa));
		}
	    }
	}
	else {
	    do_log($zone,$ns,1,"SOA for ${zone} not found at ${ns}",16,$res->errorstring);
	}
    }

    if(length($saved_email_address) > 0) {
	do_log($zone,"",3,"$saved_email_address is the mail in SOA",124);
    }
    if(length($saved_master) > 0) {
	do_log($zone,"",3,"$saved_master is the master server in SOA",129);
    }

    if($settings{bgprouter}) {
	my $numas = scalar(keys(%saved_as));
	my $theas;
	my $ases;

	if($numas > 0) {
	    foreach $ases (keys(%saved_as)) {
		$theas = $theas . " " . "$ases";
	    }
	    if($numas == 1) {
		do_log($zone,"",2,"Zone ${zone} is announced by only one AS," . $theas,30);
	    } else {
		do_log($zone,"",4,"Zone ${zone} is announced by ${numas} AS:es" . $theas,105);
	    }
	}
    }

    if($some_auth < 1) {
        do_log($zone,"",1,"No nameservers authoritative",12);
    }

    do_log($zone,"",3,"Ready with this zone",106);
    return(0);
};

sub check_child_zones {
    my ($parent,$global_check_parent) = @_;

    my $res = new_resolver;
    my @mns;
    undef @mns;
    do_log($parent,"",4,"Fetching NS for $parent",107);
    if($parent eq ".") {
	do_log($zone,"",5,"Query $parent IN NS",135);
	my $packet = $res->send($parent,"NS");
    } else {
	do_log($zone,"",5,"Query $parent IN NS",135);
	my $packet = $res->send($parent,"NS");
    }
    my $rr;
    if($packet && $packet->header->ancount > 0) {
	foreach $rr ($packet->answer) {
	    do_log($zone,"",5,"Response " . rrstring($rr),136);
	}
	foreach $rr ($packet->answer) {
	    next unless $rr->type eq "NS";
	    do_log($parent,"",3,"${parent} IN NS " . $rr->nsdname,108);
	    push @mns, $rr->nsdname;
	}
    }

    if(scalar(@mns) == 0) {
	do_log($parent,"",1,"Didn't find nameservers to do zonetransfers from",8);
	return 0;
    };

RETRYNS:
    if(scalar(@mns) == 0) {
	do_log($parent,"",1,"Failed to do zonetransfer",117);
	return 0;
    };
    my $newtry = pop(@mns);
    $res->nameservers($newtry);
    do_log($parent,$newtry,4,"Trying to do zonetransfer",109);
    do_log($zone,$newtry,5,"Query $domain. IN AXFR",135);
    my @zonefile = $res->axfr($parent);
    if(!@zonefile) {
	do_log($parent,$newtry,2,"Zonetransfer failed",26);
	goto RETRYNS;
    };
    do_log($parent,$newtry,4,"Zonetransfer worked",110);
    my @childzones;
    undef @childzones;
    foreach $rr (@zonefile) {
	do_log($zone,"",5,"Response " . rrstring($rr),136);
    }
    foreach $rr (@zonefile) {
	if($rr->type eq "NS" && lc($rr->name) ne lc($parent)) {
	    do_log($parent,$newtry,3,$rr->name . " IN NS " . $rr->nsdname,111);
	    push @childzones, $rr->name;
	}
    };
    if(scalar(@childzones) == 0) {
	do_log($parent,"",3,"Didn't find any child zones to check",18);
	return 0;
    };
    my $z;
    foreach $z (@childzones) {
	if(!$checked_zone{lc($z)}) {
	    $checked_zone{lc($z)} = 1;
	};
    };
};

sub describe_usage {
   print "USAGE: $0 [--argument=value ...] domain [domain...]\n\n";
   print "Argument --help give list of arguments available\n";
   exit;
}

sub usage {
    my ($text,$value) = @_;
    $text = $text . ": $value" if $value ne "";
    print "Error: $text\n";
    describe_usage;
};

sub get_option {
    my ($index,$defaultvalue) = @_;

    if(exists($options{$index})) {
	do_log("","",4,"Option $index is " . $options{$index},112);
	return $options{$index};
    } else {
	do_log("","",4,"Option $index is default " . $defaultvalue,113);
	return $defaultvalue;
    };
};

###### Main

settime();

# Defaults

# Name of logfile
$global_logfile = $settings{'logfile'};
open(LOGFILE, ">" . $global_logfile) or usage("Impossible to open logfile",$global_logfile);
$global_log = LOGFILE;
$global_log->autoflush(1);

# Loglevel
$global_loglevel = $settings{'debuglevel'};
usage("Illegal debug level",$global_loglevel) if $global_loglevel < 0 || $global_loglevel > 5;

# Timeout for TCP transactions in Seconds
$global_timeout = $settings{'tcptimeout'};
usage("Illegal value of TCP timeout",$global_timeout) if $global_timeout < 1;

# Timeout for UDP transactions in Seconds
$global_retrans = $settings{'udptimeout'};
usage("Illegal value of UDP timeout",$global_retrans) if $global_retrans < 1;

# Number of retries for UDP transactions
$global_retry = $settings{'udpretries'};
usage("Illegal value of retry",$global_retry) if $global_retry < 1;

# If true, check all NS at parent
$global_check_parent = $settings{'checkparent'};

# If true, check all child zones, not this one
$global_check_children = $settings{'checkchildren'};

# Number of child processes allowed
$global_children = $settings{'maxchildren'};
usage("Illegal value of child processes",$global_children) if $global_children < 1;

# Maximum number of tries with zone
$global_maxtries = $settings{'maxtries'};
usage("Illegal value of maxtries",$global_maxtries) if $global_maxtries < 1;

$router = $settings{bgprouter};
$username = $settings{bgpuser};

# Did we get any domain names?
usage("No domains named") if scalar(@argv) < 1;

# Did we get smtp request but not myemailaddr?
if($settings{smtp}) {
    if(length($settings{myemailaddr}) < 1) {
	usage("You must set myemailaddr if smtp is requested");
    }
}

my $z;

foreach $z (@argv) {
    if($global_check_children) {
	check_child_zones($z,$global_check_parent);
    } elsif(!$checked_zone{lc($z)}) {
	$checked_zone{lc($z)} = 1;
    };
};

my $numzones = 0;
my $r;
my $key;
my @zones;
foreach $key (keys %checked_zone) {
    $numzones++;
    push @zones, $key;
};

do_log("","",4,"Found $numzones zones to check",125);

####
sub do_child_stuff {
    my ($cmd) = @_;
    my $tmp = check_one_zone($cmd,$global_check_parent);
    return ($tmp);
};

sub do_idle_stuff {
};

my $num_children = $global_children;
my $idle = 1;

my $tries = 0;
while ($tries < $global_maxtries && scalar(@zones) > 0) {
    $tries++;
    do_log("","",4,"Try number $tries",126);
    my %res = apply(\&do_child_stuff, \&do_idle_stuff, $num_children, $idle, @zones);

    undef @zones;
    foreach $key (keys %res) {
	if($res{$key} == 1) {
	    push(@zones,$key);
	};
    };
};

while(defined($zone = pop(@zones))) {
    do_log($zone,"",2,"Failed $global_maxtries times with zone",33);
};
exit 0;
