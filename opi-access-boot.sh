#! /bin/sh

echo "Requesting update of signed certificates"
/usr/share/opi-access/dns_update.py
echo "Running UPNP script"
/usr/share/opi-access/opi-access.sh
