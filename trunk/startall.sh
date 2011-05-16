#!/bin/sh

./control start

#utils/ivimap add46 10.0.0.0/8 2001:abc:ff00::

#utils/ivimap add64 2001:abc:ff00::

#utils/ivimap add64 fe80:0:ff00::

utils/ivictl start eth1 eth0

