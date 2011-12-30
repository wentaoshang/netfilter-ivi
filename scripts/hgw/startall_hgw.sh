#!/bin/sh

./control start

../../utils/ivictl format suffix 16 0 2
../../utils/ivictl start eth1 eth0 202.38.111.0 24 2001:da8:c4c6:: 48

