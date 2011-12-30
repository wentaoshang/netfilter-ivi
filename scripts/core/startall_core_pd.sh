#!/bin/sh

./control start

../../utils/ivictl rule add 202.38.111.0 24 2001:da8:c3c5:: 48 16 2
../../utils/ivictl rule add default 2001:da8:c4c6:: 48

../../utils/ivictl start eth1 eth0

