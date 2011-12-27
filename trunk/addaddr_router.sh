#!/bin/sh

# configure system profile
#echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 0 > /proc/sys/net/ipv6/conf/eth0/autoconf
echo 0 > /proc/sys/net/ipv6/conf/eth1/autoconf

# configure eth0 -- interface to the core translator
ifconfig eth0 down
ifconfig eth0 up
ip -6 addr add 2001:250:3::150/64 dev eth0
ip -6 route add default via 2001:250:3::149 dev eth0

# configure eth1 -- interface to the host
ifconfig eth1 down
ifconfig eth1 up
ip -6 addr add 2001:da8:c4c6:ca26:6ffe::/72 dev eth1

