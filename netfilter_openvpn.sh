#!/bin/sh
# This is also removed after everything has been successfull by the python script.
# We remove on delete for safety in case the python script fails so that it doesn't forbid a potential future client.
operation=$1
address=$2
# Use this if you need to use "username as common name". This has security implications:
# username is arbitrary and sent by the user, common_name matches a signed certificate common bame and cannot be forged.
#common_name=${username}
export operation address common_name

SUDO=/usr/bin/sudo
IPTABLES=/sbin/iptables

if [[ ${operation} == "delete" ]]; then
	${SUDO} ${IPTABLES} -D INPUT -s ${address} -j DROP
else
	${SUDO} ${IPTABLES} -I INPUT -s ${address} -j DROP || {
		echo "Failed to run initial iptables command"
		exit 127
	}
fi

${SUDO} /usr/lib/openvpn/plugins/netfilter_openvpn.py ${operation} &
disown
exit 0
