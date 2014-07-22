#!/bin/bash
source /etc/opi/opi-access.conf

if /usr/bin/upnpc -s | grep -qs "Found valid IGD" ; then
	echo "Valid IGD found"
else
	echo "No valid IGD found"
	exit 0
fi
ipaddr=`/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'`

for port in "${!ports[@]}"
do   
  if [ ${ports[$port]} == "yes" ]; then
	echo "Opening port $port"
	/usr/bin/upnpc -a $ipaddr $port $port tcp &> /dev/null
  else
	if [ ! -z "$1" ]; then
		if [ $1 == "force" ]; then
			echo "Closing port $port"
			/usr/bin/upnpc -d $port tcp &>/dev/null
		fi
	fi
  fi
done
exit 0
