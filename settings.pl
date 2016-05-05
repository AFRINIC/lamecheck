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

use strict;

package settings;

our %settings;
our @argv;

sub default_settings {
    %settings = (
		 htmlpath      => '.',
		 settings      => '',
		 mysqldb       => '',
		 mysqluser     => '',
		 smtp          => 1,
		 myemailaddr   => 'amreesh@afrinic.net',
		 bgprouter     => '',
		 bgpuser       => '',
		 maxchildren   => 1,
		 checkparent   => 0,
		 tcptimeout    => 15,
		 udptimeout    => 2,
		 udpretries    => 4,
		 debuglevel    => 1,
		 maxtries      => 3,
		 logfile       => '-',
		 help          => '',
		 zonecheck     => './dns.pl',
		 dnsservers    => '',
		 checkchildren => 0,
		 );
}

sub usage {

    my $key;

    %settings = default_settings;
    print "USAGE: $0 [--argument=value ...] command [command-arguments ...]\n\n";
    print "The following arguments are available (with default values):\n";

    foreach $key (keys(%settings)) {
	printf " %20s %s\n","--" . $key,$settings{$key};
    };
    exit 0;
}

sub parse_argv {
    my $num=0;
    my $s=0;
    my @saved;
    while($num <= $#ARGV) {
	  $_=$ARGV[$num];
	  if(/^--/) {
	      s/^--//;
	      if(/^help$/) {
		  usage;
	      }
	      my ($var,@val) = split(/=/);
	      unless (defined($settings{$var})) {
		  print "$var is not a valid argument\n\n";
		  usage;
	      }
	      $settings{$var} = join('=',@val);
	  } else {
	      $saved[$s]=$ARGV[$num];
	      $s++;
	  }
	  $num++;
    }
    return @saved;
}

sub init_settings {
    %settings = default_settings;
    @argv=parse_argv();
    
    if(length($settings{'settings'}) <= 0) {
	return;
    }
    unless(open(S,$settings{'settings'})) {
	printf "Can not open settings file %s\n\n",$settings{'settings'};
	usage;
    }
    while(<S>) {
	chomp;
	if(/^[^#]/) {
	      my($variable,$value) = split(/=/);
	      unless (defined $settings{$variable}) {
		  printf "Setting %s found in file %s is not valid\n\n",$variable,$settings{'settings'};
	    usage;
	      } else {
		  $settings{$variable}=$value;
	      }
	}
    }
    close(S);
    @argv=parse_argv();
}

init_settings;
