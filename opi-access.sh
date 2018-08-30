#!/bin/bash

if /usr/bin/upnpc -s | grep -qs "Found valid IGD" ; then
	echo "Valid IGD found"
else
	echo "No valid IGD found"
	exit 0
fi

netif=$(kgp-sysinfo -p -u | grep "NetworkDevice" | awk -F':' '{print$2}')
ipaddr=$(/sbin/ifconfig $netif | grep 'inet\s' | awk '{print $2}')

ports=$(kgp-sysinfo -p -c upnp -k forwardports)
if [[ $? -ne 0 ]]; then
	echo "Unable to get ports to forward."
	exit 1
fi

for port in $ports
do   
	echo "Opening port $port"
	/usr/bin/upnpc -a $ipaddr $port $port tcp &> /dev/null
done
exit 0
