#!/bin/sh

# configure system profile
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 0 > /proc/sys/net/ipv6/conf/eth0/autoconf
echo 0 > /proc/sys/net/ipv6/conf/eth1/autoconf

# configure eth0 -- IPv6 interface
ifconfig eth0 up
ifconfig eth0 inet6 add 2001:da8:123:456:202:201::/88

# configure eth1 -- IPv4 interface
ifconfig eth1 up
ifconfig eth1 1.1.1.254/24

