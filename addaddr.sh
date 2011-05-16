#!/bin/sh

# configure system profile
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 0 > /proc/sys/net/ipv6/conf/eth0/autoconf
echo 0 > /proc/sys/net/ipv6/conf/eth1/autoconf

# configure eth0 -- IPv6 interface
ifconfig eth0 up
ifconfig eth0 inet6 add 2001:da8:a123:b456:202:201::/88
#route --inet6 add default gw 2001:abc:ff0a:10a:a00::
#route --inet6 add ff3e::/16 gw 2001:abc:ff0a:10a:a00::

# configure eth1 -- IPv4 interface
ifconfig eth1 up
ifconfig eth1 1.1.1.254/24
#route add -net 10.0.0.0/8 gw 10.1.10.1

