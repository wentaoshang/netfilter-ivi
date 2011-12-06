#!/bin/sh

# configure system profile
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 0 > /proc/sys/net/ipv6/conf/eth0/autoconf
echo 0 > /proc/sys/net/ipv6/conf/eth1/autoconf

# configure eth0 -- IPv6 interface
ifconfig eth0 up
ifconfig eth0 inet6 add 2001:250:3::150/64
ip -6 route add default via 2001:250:3::149 dev eth0

# configure eth1 -- IPv4 interface
ifconfig eth1 up
ifconfig eth1 1.1.1.254/24

# Add virtual route info for IPv4. This route is used only when forwarding packets with TTL = 1.
# The gw is invalid since eth0 is the IPv6 interface. See 'ivi_xmit.c' for more information.
ifconfig eth0 202.38.101.44/26
route add default gw 202.38.101.1 eth0

# Add virtual route info for IPv6. See above for the reason to do this.
ifconfig eth1 inet6 add 2001:da8:a123:500::/64
ip -6 route add 2001:da8:c4c6:ca26:6f00::/72 via 2001:da8:a123:500::1 dev eth1
