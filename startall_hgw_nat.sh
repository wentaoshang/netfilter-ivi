#!/bin/sh

./control start

utils/ivictl format suffix 16 0
utils/ivictl start eth1 eth0 1.1.1.0 24 202.38.111.2 2001:da8:c4c6:: 48

