#!/bin/sh

ip route add default via 192.168.56.1 dev eth0

ip -6 addr add 2001:123:456:c0a8:3865:4000::/72 dev eth0

ip -6 route add default via fe80::a00:27ff:fe00:f408 dev eth0
