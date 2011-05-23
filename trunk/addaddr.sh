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

# Add virtual route info for IPv4. This route is used only when forwarding packets with TTL = 1.
# The gw is invalid since eth0 is the IPv6 interface. See 'ivi_xmit.c' for more information.
ifconfig eth0 2.2.2.1/24
#route add default gw 2.2.2.254 eth0

# Add virtual route info for IPv6. See above for the reason to do this.
ifconfig eth1 inet6 add 2001:da8:123:456:101:1fe::/88
