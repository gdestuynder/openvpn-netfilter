#! /usr/bin/env bash
#  ulfr - 2013
if [ -z $1 ]; then
    /bin/echo "usage: $0 <user ip>"
    /bin/echo "find the firewall rules for a specific VPN IP and delete them all"
    exit 1
fi
userip="$1"
TMP="$(mktemp)-$userip"
/sbin/iptables-save|/bin/grep -E "\-(s|d) $userip/32"|/bin/sed -e "s/-A/\/sbin\/iptables -D/" > $TMP
/bin/echo "/sbin/iptables -F $userip" >> $TMP
/bin/echo "/sbin/iptables -X $userip" >> $TMP
/bin/echo "/usr/sbin/ipset --destroy $userip" >> $TMP
#echo "Stored $(wc -l $TMP|awk '{print $1}') cleanup rules in $TMP"
/bin/bash $TMP
/bin/rm "$TMP"
