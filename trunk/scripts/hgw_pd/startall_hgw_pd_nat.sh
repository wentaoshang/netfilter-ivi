#!/bin/sh

./control start

../../utils/ivictl -r -d -P 2001:da8:c4c6:: -L 48

../../utils/ivictl -s -i eth1 -I eth0 -H -N -p 1.1.1.0 -l 24 -A 202.38.111.2 -P 2001:da8:c3c5:: -L 48 -R 16 -M 2 -o 0 -f suffix
