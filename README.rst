openvpn-netfilter
=================

Per VPN user network ACLs using Netfilter and OpenVPN.

Setup
=====

While the script is fast, it still hangs OpenVPN for a second while running, which may be felt by VPN users.
To minimize the impact the script blocks all connections then fork off and return control to openvpn.
The fork finishes the rule setup.

.. code::

   learn-address /usr/lib/openvpn/plugins/netfilter_openvpn.sh

If using LDAP for user authentication, add this to the OpenVPN server configuration:

.. code::

    username-as-common-name

For any OpenVPN server configuration, also add this (or a sudo wrapper to this script, if needed. You may also use capabilities.):

.. code::

    #This is necessary so that openvpn delete the ip after 20s, assuming the client has gone away
    #This may not be needed for TCP VPNs since the VPN knows when the client has gone away. (have not tested)
    #For the same reason, remember to kill a client for at least 20s, or SIGUSR1 openvpn if you're changing ACLs for that client.
    keepalive 10 20

Change the settings in /etc/openvpn/netfilter_openvpn.conf.

In general, you'll want to store the rules in /etc/openvpn/netfilter/rules/* and have a list of files such as "vpn_teamA.rules".
Users belonging to the LDAP group name teamA will get those rules.
You'll also want to have /etc/openvpn/netfilter/users/* for per user rules.
Likewise, make sure that the paths of the 'iptables', 'ipset', and 'vpn-netfilter-cleanup-ip.sh' commands are correct for your system.

Don't forget to push the proper routing rules for the network/IPs you allow.

Rule format
===========
Rules are formatted as list of ips or networks (anything netfilter understands for an address or network really), such as:

.. code::

    # Lines starting with a # sign can be used for comments
    127.0.0.1
    127.0.0.1/27
    # Obviously you might want to use slightly more useful rules ;-)

Script logic
============

learn-address is an OpenVPN hook called when the remote client is being set an IP address at the VPN server side. It calls the netfilter script, which in turn will load the netfilter (iptables) rules for that IP address, per given cn name (cn name is the username in the certificate, or the LDAP user name).

If the script fails for any reason, OpenVPN will deny packets to come through.

When a user successfully connects to OpenVPN, netfilter.py will create a set for firewall rules for this user. The custom rules are added into a new chain named after the VPN IP of the user:

.. code::

    Chain 172.16.248.50 (3 references)
     pkts bytes target     prot opt in     out     source               destination
     5925  854K ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           ctstate ESTABLISHED /* ulfr at 172.16.248.50 */
      688 46972 ACCEPT     all  --  *      *       172.16.248.50        0.0.0.0/0           match-set 172.16.248.50 dst /* ulfr groups: vpn_caribou;vpn_pokemon;vpn_ninjas;*/
       24  2016 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0           /* ulfr at 172.16.248.50 */ LOG flags 0 level 4 prefix `DROP 172.16.248.50'
       24  2016 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0           /* ulfr at 172.16.248.50 */


A jump target is added to INPUT, OUTPUT and FORWARD to send all traffic originating from the VPN IP to the custom chain:

.. code::

    Chain INPUT (policy ACCEPT 92762 packets, 15M bytes)
     3320  264K 172.16.248.50  all  --  *      *       172.16.248.50         0.0.0.0/0
    Chain OUTPUT (policy ACCEPT 136K packets, 138M bytes)
     2196  549K 172.16.248.50  all  --  *      *       0.0.0.0/0            172.16.248.50
    Chain FORWARD (policy ACCEPT 126K packets, 127M bytes)
     1120 90205 172.16.248.50  all  --  *      *       172.16.248.50         0.0.0.0/0


You'll notice the comments are there for ease of troubleshooting, you can grep through "iptables -L -n" and find out which user or group has access to what easily.

To reduce the amount of rules created, when the LDAP ACLs only contains a list of destination subnets, these subnets are added into an IPSet. The IPSet is named after the VPN IP of the user.

.. code::

    --- IPSET HASH TABLE ---
    Name: 172.16.248.50
    Type: hash:net
    Header: family inet hashsize 1024 maxelem 65536
    Size in memory: 17968
    References: 1
    Members:
    172.39.72.0/24
    172.31.0.0/16
    172.11.92.150
    42.89.217.202

Maintenance
===========
You can list the rules and sets of a particular user with the script named 'vpn-fw-find-user.sh'.

You can delete all of the rules and sets of a given VPN IP using the script named 'vpn-netfilter-cleanup-ip.sh'.
