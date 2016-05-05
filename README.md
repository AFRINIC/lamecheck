# lamecheck
some code snippets to check lameness of a zone

sh dnscheck.sh <domain> <nameserver>

CASE_0: all good not lame
CASE_1: server not reachable, nameserver cannot be resolved, port 53 closed etc
CASE_3: nameserver reachable but not responsive or not serving zone
CASE_4: nameserver not authoritative

RECURSIVE tag: a nameserver is tagged as recursive if the flag "ra" is found. Authoritative nameservers should normally not be open recursive server as they can be vulnerable to DDoS.

A zone is considered lame is one of the above conditions are met. The dnscheck script is a simple bash script which uses "dig" and parses the output.


