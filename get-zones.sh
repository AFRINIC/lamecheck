#!/usr/bin/env bash

# quick'n'dirty script to wget all AFRINIC zones
# stuff is hard-coded. that's the way it is :)
# expectation of `wget` in $PATH

wget -e robots=off --wait 1 -r http://ftp.afrinic.net/pub/zones/
mv ftp.afrinic.net/pub/zones/*.arpa-AFRINIC zones/
rm -r ftp.afrinic.net
