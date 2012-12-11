openvpn-netfilter
=================

Per VPN user network ACLs using Netfilter and OpenVPN.

SETUP
=====

If using LDAP for user authentication, add this to the OpenVPN server configuration:

    username-as-common-name

For any OpenVPN server configuration, also add this (or a sudo wrapper to this script, if needed. You may also use capabilities.):

    learn-address /etc/openvpn/netfilter/netfilter.py
    #This is necessary so that openvpn delete the ip after 20s, assuming the client has gone away
    #This may not be needed for TCP VPNs since the VPN knows when the client has gone away. (have not tested)
    #For the same reason, remember to kill a client for at least 20s, or SIGUSR1 openvpn if you're changing ACLs for that client.
    keepalive 10 20

Change the settings at the top of the netfilter.py file. In general, you'll want to store the settings in /etc/openvpn/netfitler/rules/* and have a list of files such as "vpn_teamA.rules". Users belonging to the LDAP group name teamA will get those rules.
You'll also want to have /etc/openvpn/netfilter/users/* for per user rules.

Don't forget to push the proper routing rules for the network/IPs you allow.

RULE FORMAT
===========
Rules are formatted as list of ips or networks (anything netfilter understands for an address or network really), such as:

    # Lines starting with a # sign can be used for comments
    127.0.0.1
    127.0.0.1/27
    # Obviously you might want to use slightly more useful rules ;-)

SCRIPT LOGIC
============

learn-address is an OpenVPN hook called when the remote client is being set an IP address at the VPN server side. It calls the netfilter script, which in turn will load the netfilter (iptables) rules for that IP address, per given cn name (cn name is the username in the certificate, or the LDAP user name).

If the script fails for any reason, OpenVPN will deny packets to come through.

Each user access is represented by a new netfilter chain named by it's local VPN ip, such as:

    Chain INPUT (policy ACCEPT)
    target     prot opt source               destination         
    10.22.248.10  all  --  10.22.248.10         anywhere 

And the equivalent OUTPUT chain.


The user chain looks like:

    Chain 10.22.248.10 (2 references)
    target     prot opt source               destination         
    ACCEPT     all  --  10.22.248.10         10.250.64.0/22      /* username:vpn_teamname */ 
    ACCEPT     all  --  10.250.64.0/22       10.22.248.10        /* username:vpn_teamname */
    DROP       all  --  any                  any


You'll notice the comments are there for ease of troubleshooting, you can grep through "iptables -L -n" and find out which user or group has access to what easily.
