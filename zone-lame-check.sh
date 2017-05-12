#!/usr/bin/env bash

set -e 

# Tries to download a DNS zone file by testing one after the other all
# its authoritative name servers. 

sigint() {
	echo Bye
	exit 1
}

trap sigint INT

unset LANG
unset LC_MESSAGES

if [ -z "$1" ]; then
   echo "Usage: $0 zone authns" >&2
   exit 1
fi

zone=$(echo "$1" |sed -e 's/\.$//')
ns=$(echo "$2" | sed -e 's/\.$//')

#tmp=$(mktemp /tmp/.try-get-zone.XXXXXXXXXX)
tmp="/tmp/out.lame"
#if ! dig @${ns} +norec NS ${qualifiedzone} > $tmp 2>&1; then
#   echo "Error with ${ns}" >&2
#   continue
#fi

dig @${ns} +norec NS ${zone} &> $tmp | tee $tmp

if egrep "connection timed out|Name or service not known|connection refused|network unreachable|host unreachable|end of file|communications error|couldn't get address" $tmp > /dev/null; then
    echo "$zone,$ns,LAME,CASE_1"
    exit 1;
fi

if egrep "status: REFUSED|status: SERVFAIL|status: NXDOMAIN" $tmp > /dev/null; then
	error=$(egrep -o "REFUSED|SERVFAIL|NXDOMAIN" $tmp)
        echo "$zone,$ns,LAME,CASE_3:"$error
	exit 3;
fi

if egrep "status: NOERROR" $tmp > /dev/null;then
	if egrep "ANSWER: 0" $tmp > /dev/null;then
        	echo "$zone,$ns,LAME,CASE_3:NO_ANSWER"
		exit 3;
        fi
	if ! egrep "flags: qr.+aa.+" $tmp > /dev/null; then
		if egrep "flags: qr.+ra.+" $tmp > /dev/null; then
			echo "$zone,$ns,LAME,CASE_4:RECURSIVE"
		else
			echo "$zone,$ns,LAME,CASE_4"
		fi
		exit 4;
	fi
fi

if egrep "status: NOERROR" $tmp > /dev/null;then
	if egrep "flags: qr.+ra.+" $tmp > /dev/null; then
		echo "$zone,$ns,OK,CASE_0:RECURSIVE"
	else
		echo "$zone,$ns,OK,CASE_0"
	fi
	exit 0;
fi

exit -1
