#!/bin/sh
echo "ADDR $(hostname -I)"
echo "ROUTE $(awk 'NR>1 && $2=="00000000"{print $1, $3}' /proc/net/route)"
echo "RESOLV $(grep nameserver /etc/resolv.conf)"
echo "RESOLV-WRITE $( (: >>/etc/resolv.conf) 2>&1 && echo ok)"
spike-guest tcp 10.0.2.2:8080 hello-from-guest
echo "ARP $(awk 'NR>1{print $1, $4, $6}' /proc/net/arp)"
