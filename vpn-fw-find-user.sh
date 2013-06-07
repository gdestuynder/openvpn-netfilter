#! /usr/bin/env bash
# ulfr - 2013
if [ -z $1 ]; then
    echo "usage: $0 <user cn>"
    echo "search for a vpn user that matches the input, and display all firewall rules"
    exit 1
fi
usercn=$1
useriplist=$(iptables -L -v -n |grep "$usercn"|grep match-set|awk '{print $11}')
groupslist=$(echo $(iptables -L -v -n |grep "$usercn"|grep match-set|awk '{print $16}')|tr ";" "\n")

for userip in $useriplist; do
    echo -e "-------------------------------\n--- $usercn has IP $userip ---"
    echo -e "ldap groups:\n$(for g in $groupslist; do echo "- $g";done)"
    echo -e "\n--- IPTABLES RULES ---"
    for chain in INPUT OUTPUT FORWARD; do
        iptables -L $chain -v -n |grep -E "Chain $chain|$userip"
    done
    iptables -L $userip -v -n
    echo
    echo -e "\n--- IPSET HASH TABLE ---"
    ipset --list $userip
    echo -e "--- end of $usercn $userip ---\n-------------------------------"
done
