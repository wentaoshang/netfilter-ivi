#!/bin/sh

# config IPv4 address and route
#ifconfig eth0 down
#ifconfig eth0 up
#ifconfig eth0 202.38.111.2/24
#ip route add default via 202.38.111.254 dev eth0

# config IPv6 address and route
ip -6 addr add 2001:da8:c4c6:ca26:6f02:4000::/72 dev eth0
ip -6 route add default via 2001:da8:c4c6:ca26:6ffe:: dev eth0
