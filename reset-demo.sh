#!/bin/bash

default_bigips="10.11.50.201 10.11.50.202 10.11.50.203"

bigips=${1:-$default_bigips}

for i in $bigips;
    do 
	echo "Logging into $i"
	#ssh root@${i} "tmsh load /sys config default; tmsh delete sys management-route all; tmsh save /sys config; rm -f /config/bigip.license; reloadlic; touch /var/avr/init_avrdb; bigstart restart monpd;"
	ssh root@${i} "tmsh load /sys config default; tmsh delete sys management-route all; tmsh save /sys config; rm -f /config/bigip.license; reloadlic;"
	#ssh root@${i} "/bin/hostname"
    done

