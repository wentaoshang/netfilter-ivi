#!/bin/sh

./control start

../../utils/ivictl -r -p 202.38.111.0 -l 24 -P 2001:da8:c4c6:: -L 48
../../utils/ivictl -r -d -P 2001:da8:c4c6:: -L 48

../../utils/ivictl -s -i eth1 -I eth0

