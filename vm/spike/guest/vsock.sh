#!/bin/sh
echo "IFACES $(awk -F: 'NR>2{printf "%s ", $1}' /proc/net/dev)"
spike-guest tcp 1.1.1.1:80 x
spike-guest vsock-rtt 5000 1000
