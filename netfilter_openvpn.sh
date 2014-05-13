#!/bin/sh
# This is also removed after everything has been successfull by the python script.
# We remove on delete for safety in case the python script fails so that it doesn't forbid a potential future client.
if [[ ${operation} == "delete" ]]; then
	iptables -D INPUT -s ${address} -j DROP
else
	iptables -I INPUT -s ${address} -j DROP || {
		echo "Failed to run initial iptables command"
		exit 127
	}
fi

/usr/lib/openvpn/plugins/netfilter_openvpn.py &
disown
exit 0
