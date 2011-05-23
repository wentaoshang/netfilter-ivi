#!/bin/sh

./control start

# utils/ivictl format suffix 256 1
utils/ivictl start eth1 eth0 1.1.1.0 24 2001:da8:123:456:: 64

