#!/bin/sh

./control start

utils/ivictl format suffix 16 0

utils/ivictl start 192.168.56.0 24 2001:123:456:: 48

