#!/bin/sh
#
# ip_masquerade.sh: sets IP masquerading.
# This script is executed by NetsukukuD at its start (if in restricted mode).
# If all went ok the exit status is 0, otherwise NetsukukuD will stop.
#
# "ip_masquerade stop" is executed when NetsukukuD is closed.

#EXTIF="$1"

PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin/
OS=`uname`

masq_start() {
	if test $OS = "Linux"
	then
		# Flush all the NAT rules
		iptables -F POSTROUTING -t nat  

		# Dynamic IP users:
		#
		#   If you get your IP address dynamically from SLIP, PPP, or DHCP, 
		#   enable this following option.  This enables dynamic-address hacking
		#   which makes the life with Diald and similar programs much easier.
		#
		# echo "1" > /proc/sys/net/ipv4/ip_dynaddr

		# Masquerade
		iptables -A POSTROUTING -t nat -j MASQUERADE ! -o lo

		# Static IP users: 
		#
		#   If you have a connection with a static IP comment the previous rule
		#   and use this instead.
		#
		# iptables -t nat -A POSTROUTING -o ppp0 -j SNAT --to $INTERNET_IP

		exit $?
	fi
}

masq_stop() {
	if test $OS = "Linux"
	then
		# Flush all the NAT rules
		iptables -F POSTROUTING -t nat
		exit $?
	fi
}

case "$1" in
'start')
  masq_start
  ;;
'stop')
  masq_stop
  ;;
'help')
    echo "Usage: $0 {start|stop|help}"
    exit 1
  ;;
*)
  masq_start
esac

exit 1
