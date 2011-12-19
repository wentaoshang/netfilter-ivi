#!/bin/sh

# install modules
./control start

# disable gso and tso on network device
utils/ivictl device eth0

# set address format and ratio & offset
utils/ivictl format suffix 16 0

# set ivi mapping prefix and start ivi
utils/ivictl start 192.168.56.101 24 2001:123:456:: 48

