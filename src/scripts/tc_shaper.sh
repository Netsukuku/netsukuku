#!/bin/sh
#
# tc_shaper.sh: shapes the upload Internet traffic. This script is an
# adaptation of the Wonder Shaper script, see http://lartc.org/wondershaper
#
# This script is executed by NetsukukuD at its start (if in restricted mode).
# The returned exit status of the script is 0 if no error has occurred
# is 0
#

PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin/"

#########################################################
# Modify these values to your needs	
#

# Give absolute priority to the traffic going to `LOCAL_SUBNET'
LOCAL_SUBNET=192.168.0.0/16 

# Shape the ingoing traffic (it isn't advised), set it to 1 if you want to
# activate it
SHAPE_DOWNLINK=

# low priority OUTGOING traffic - you can leave this blank if you want
# low priority source netmasks
NOPRIOHOSTSRC=80

# low priority destination netmasks
NOPRIOHOSTDST=

# low priority source ports
NOPRIOPORTSRC=

# low priority destination ports
NOPRIOPORTDST=
#########################################################

if test -z "$1" -o "$1" = "help"
then
	echo "Usage: $0 device upload_bw download_bw"
	echo "       $0 stop device"
	exit 1
fi

#
# These parameters are set by NetsukukuD
# `$1' is the device to be shaped
# `$2' is the upload Inet bandwidth in Kilobytes/seconds
# `$3' is the download Inet bandwidth in Kilobytes/seconds
#
DEV=$1
if test "$1" = "stop"; then
	if test -z "$2"; then
		echo specify the device to stop
		exit 1
	fi
	DEV="$2"
else
	UPLINK=`expr 2 '*' 8`
	DOWNLINK=`expr $3 '*' 8`
fi

# clean existing down and uplink qdiscs, hide errors
tc qdisc del dev $DEV root    2> /dev/null > /dev/null
tc qdisc del dev $DEV ingress 2> /dev/null > /dev/null

if test "$1" = "stop"
then 
	exit 0
fi


####
###### uplink
####

# install root CBQ

tc qdisc add dev $DEV root handle 1: cbq avpkt 1000 bandwidth 10mbit 

# shape everything at $UPLINK speed - this prevents huge queues in your
# DSL modem which destroy latency:
# main class

tc class add dev $DEV parent 1: classid 1:1 cbq rate ${UPLINK}kbit \
allot 1500 prio 5 bounded isolated

#no limit class
tc qdisc add dev $DEV parent 1:1 handle 11: pfifo

# high prio class 1:10:

tc class add dev $DEV parent 1:1 classid 1:10 cbq rate ${UPLINK}kbit \
   allot 1600 prio 1 avpkt 1000

# bulk and default class 1:20 - gets slightly less traffic, 
#  and a lower priority:

tc class add dev $DEV parent 1:1 classid 1:20 cbq rate $[9*$UPLINK/10]kbit \
   allot 1600 prio 2 avpkt 1000

# 'traffic we hate'

tc class add dev $DEV parent 1:1 classid 1:30 cbq rate $[8*$UPLINK/10]kbit \
   allot 1600 prio 2 avpkt 1000

# all get Stochastic Fairness:
tc qdisc add dev $DEV parent 1:10 handle 10: sfq perturb 10
tc qdisc add dev $DEV parent 1:20 handle 20: sfq perturb 10
tc qdisc add dev $DEV parent 1:30 handle 30: sfq perturb 10

# Give priority to traffic going to the LAN
if test ! -z "$LOCAL_SUBNET"
then
	tc filter add dev $DEV parent 1:0 prio 1 protocol ip u32 match  \
	ip dst "$LOCAL_SUBNET" flowid 1:1
fi

# start filters
# TOS Minimum Delay (ssh, NOT scp) in 1:10:
tc filter add dev $DEV parent 1:0 protocol ip prio 10 u32 \
      match ip tos 0x10 0xff  flowid 1:10
      
# DNS has priority
tc filter add dev $DEV parent 1:0 prio 10 protocol ip u32 match ip dport 53 0xffff flowid 1:10

# ICMP (ip protocol 1) in the interactive class 1:10 so we 
# can do measurements & impress our friends:
tc filter add dev $DEV parent 1:0 protocol ip prio 11 u32 \
        match ip protocol 1 0xff flowid 1:10

# prioritize small packets (<64 bytes)

tc filter add dev $DEV parent 1: protocol ip prio 12 u32 \
   match ip protocol 6 0xff \
   match u8 0x05 0x0f at 0 \
   match u16 0x0000 0xffc0 at 2 \
   flowid 1:10

###
#### Bad traffic
###

for a in $NOPRIOPORTDST
do
	tc filter add dev $DEV parent 1: protocol ip prio 14 u32 \
	   match ip dport $a 0xffff flowid 1:30
done

for a in $NOPRIOPORTSRC
do
 	tc filter add dev $DEV parent 1: protocol ip prio 15 u32 \
	   match ip sport $a 0xffff flowid 1:30
done

for a in $NOPRIOHOSTSRC
do
 	tc filter add dev $DEV parent 1: protocol ip prio 16 u32 \
	   match ip src $a flowid 1:30
done

for a in $NOPRIOHOSTDST
do
 	tc filter add dev $DEV parent 1: protocol ip prio 17 u32 \
	   match ip dst $a flowid 1:30
done

###
#### Rest is 'non-interactive' ie 'bulk' and ends up in 1:20
###
tc filter add dev $DEV parent 1: protocol ip prio 18 u32 \
   match ip dst 0.0.0.0/0 flowid 1:20


if test ! -z "$SHAPE_DOWNLINK"
then
	########## downlink #############
	# slow downloads down to somewhat less than the real speed  to prevent 
	# queuing at our ISP. Tune to see how high you can set it.
	# ISPs tend to have *huge* queues to make sure big downloads are fast
	#
	# attach ingress policer:

	tc qdisc add dev $DEV handle ffff: ingress

	# filter *everything* to it (0.0.0.0/0), drop everything that's
	# coming in too fast:

	tc filter add dev $DEV parent ffff: protocol ip prio 50 u32 match ip src \
	0.0.0.0/0 police rate ${DOWNLINK}kbit burst 10k drop flowid :1
fi

exit 0
