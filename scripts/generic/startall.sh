#!/bin/sh

./control start

../../utils/ivictl -r -d -P 2001:da8:c4c6:: -L 48

../../utils/ivictl -s -i eth1 -I eth0 -H -p 1.1.1.0 -l 24 -P 2001:da8:123:456:: -L 64

