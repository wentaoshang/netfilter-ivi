#!/bin/sh

# install modules
./control start

# disable gso and tso on network device
utils/ivictl device eth0

# set address format and ratio & offset & adjacent
utils/ivictl format suffix 16 0 2

# set ivi mapping prefix and start ivi
utils/ivictl start 202.38.111.2 24 2001:da8:c4c6:: 48 2001:da8:c4c6:: 48

