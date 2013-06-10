#!/usr/bin/env python
# Requires:
# python-ldap
#
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the netfilter.py for OpenVPN learn-address.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2012
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# gdestuynder@mozilla.com (initial author)
# jvehent@mozilla.com (refactoring, ipset support)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

import os
import sys
import ldap
import syslog

LDAP_URL='ldap://<%= ldap_server %>'
LDAP_BIND_DN='uid=<%= bind_user %>,ou=logins,dc=mozilla'
LDAP_BIND_PASSWD='<%= bind_password %>'
LDAP_BASE_DN='ou=groups,dc=mozilla'
LDAP_FILTER='cn=vpn_*'

CEF_FACILITY=syslog.LOG_LOCAL4
NODENAME=os.uname()[1]
IPTABLES='/sbin/iptables'
IPSET='/usr/sbin/ipset'
RULESCLEANUP='<%= confdir %>/plugins/netfilter/vpn-netfilter-cleanup-ip.sh'
RULES='<%= confdir %>/plugins/netfilter/rules'
PER_USER_RULES_PREFIX='users/vpn_'

def log(msg):
	"""
		Send a message to syslog
	"""
	syslog.openlog('OpenVPN', 0, syslog.LOG_DAEMON)
	syslog.syslog(syslog.LOG_INFO, msg)
	syslog.closelog()

def cef(msg1, msg2):
	"""
		Build a log message in CEF format and send it to syslog
	"""
	syslog.openlog('OpenVPN', 0, CEF_FACILITY)
	cefmsg = 'CEF:{v}|{vendor}|{dev}|{dev_v}|{sig}|{name}|{lvl}|{ext}'.format(
		v='0',
		vendor='Mozilla',
		dev='OpenVPN',
		dev_v='1.0',
		sig='',
		name=msg1,
		lvl='5',
		ext=msg2 + ' dhost=' + NODENAME,
	)
	syslog.syslog(syslog.LOG_INFO, cefmsg)
	syslog.closelog()

class IptablesFailure (Exception):
	pass

def iptables(args, raiseEx=True):
	"""
		Load the firewall rule received as argument on the local system, using
		the iptables binary

		Return: True on success, Exception on error if raiseEX=True
				False on error if raiseEx=False
	"""
	command = "%s %s" % (IPTABLES, args)
	status = os.system(command)
	if status == -1:
		raise IptablesFailure("failed to invoke iptables (%s)" % (command,))
	status = os.WEXITSTATUS(status)
	if raiseEx and (status != 0):
		raise IptablesFailure("iptables exited with status %d (%s)" %
								(status, command))
	if (status != 0):
		return False
	return True

class IpsetFailure (Exception):
	pass

def ipset(args, raiseEx=True):
	"""
		Manages an IP Set using the ipset binary

		Return: True on success, Exception on error if raiseEX=True
				False on error if raiseEx=False
	"""
	command = "%s %s" % (IPSET, args)
	status = os.system(command)
	if status == -1:
		raise IpsetFailure("failed to invoke ipset (%s)" % (command,))
	status = os.WEXITSTATUS(status)
	if raiseEx and (status != 0):
		raise IpsetFailure("ipset exited with status %d (%s)" %
							(status, command))
	if (status != 0):
		return False
	return True

def build_firewall_rule(name, usersrcip, destip, destport=None, protocol=None,
						comment=None):
	"""
		This function will select the best way to insert the rule in iptables.
		If protocol+dport are defined, create a simple iptables rule.
		If only a destination net is set, insert it into the user's ipset.

		Arguments:
			'protocol', 'destport' and 'comment' are optional
			'destport' requires 'protocol'
	"""
	if comment:
		comment = " -m comment --comment \"" + comment + "\""
	if destport and protocol:
		destport = ' -m multiport --dports ' + destport
		protocol = ' -p ' + protocol
		rule = "-A {name} -s {srcip} -d {dstip} {proto}{dport}{comment} -j ACCEPT".format(
					name=name,
					srcip=usersrcip,
					dstip=destip,
					dport=destport,
					proto=protocol,
					comment=comment
				)
		iptables(rule)
	else:
		entry = "--add {name} {dstip}".format(name=name, dstip=destip)
		ipset(entry)

def fetch_ips_from_file(fd):
	"""
		Read the IPs from a local file and return them into a dictionary
	"""
	rules = []
	line = fd.readline()
	while line != '':
		if line.startswith('#'):
			line = fd.readline()
			continue
		rules.append(line.split("\n")[0])
		line = fd.readline()
	return rules

def load_ldap():
	"""
		Query the LDAP directory for a full list of VPN groups.
		We don't filter on the user because the format of the user DN can vary.
		LDAP returns group members and IPs, that are stripped and parsed
		into a dictionary.

		Returns: a sdictionary of the form
			schema = {	'vpn_group1':
							{'cn':
								['noob1@mozilla.com',
								'noob2@mozilla.com'],
							'networks':
								['192.168.0.1/24',
								'10.0.0.1/16:80 #comment',
								'10.0.0.1:22']
							},
						'vpn_group2': ...
					 }
	"""
	conn = ldap.initialize(LDAP_URL)
	conn.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWD)
	res = conn.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, LDAP_FILTER,
						['cn', 'member', 'ipHostNumber'])
	schema = {}
	for grp in res:
		ulist = []
		hlist = []
		group = grp[1]['cn'][0]
		for u in grp[1]['member']:
			try:
				ulist.append(u.split('=')[1].split(',')[0])
			except:
				log("Failed to load user from LDAP: %s at group %s, skipping" %
					(u, group))
		if grp[1].has_key('ipHostNumber'):
			hlist = grp[1]['ipHostNumber']
		schema[group] = {'cn': ulist, 'networks': hlist}
	return schema

def load_group_rule(usersrcip, usercn, dev, group, networks, uniq_nets):
	"""
		Receive the LDAP ACLs for this user, and parse them into iptables rules
		If no LDAP rule is submitted, try to load them from a local file
	"""
	if len(networks) != 0:
		for net in networks:
			"""
				the attribute stored in net (ipHostNumber) contains 2 values:
				'<CIDR usersrcip:port> # <comment>'
				split on the '#' character to extract the comment, then split
				on the ':' character to extract IP and Port
			"""
			ipHostNumber = net.split("#")
			destination = ipHostNumber[0].strip()

			if destination in uniq_nets:
				""" Skip duplicated destinations """
				continue
			uniq_nets.append(destination)

			ldapcomment = ""
			if len(ipHostNumber) >= 2:
				ldapcomment = ipHostNumber[1] # extract the comment
			comment = usercn + ':' + group + ' ldap_acl ' + ldapcomment

			destarray = destination.split(':')
			destip = destarray[0]
			destport = ''
			if len(destarray) >= 2:
				destport = destarray[1]
				for protocol in ['tcp', 'udp']:
					build_firewall_rule(usersrcip, usersrcip, destip, destport,
										protocol, comment)
			else:
				build_firewall_rule(usersrcip ,usersrcip, destip, '', '',
									comment)
	else:
		rule_file = RULES + "/" + group + '.rules'
		try:
			fd = open(rule_file)
		except:
			# Skip if file is not found
			log("Failed to open rule file '%s' for user '%s', skipping group" %
				(rule_file, usercn))
			return

		comment = usercn + ':' + group + ' file_acl'
		for destip in fetch_ips_from_file(fd):
			# create one rule for each direction
			build_firewall_rule(usersrcip, usersrcip, destip, '', '', comment)
			build_firewall_rule(usersrcip, destip, usersrcip, '', '', comment)
		fd.close()

def load_per_user_rules(usersrcip, usercn, dev):
	"""
		Load destination IPs from a flat file that exists on the VPN gateway,
		and create the firewall rules accordingly.
		This feature does not use LDAP at all.

		This feature is rarely used, and thus the function will simply exit
		in silence if no file is found.
	"""
	rule_file = RULES + "/" + PER_USER_RULES_PREFIX + usercn
	try:
		fd = open(rule_file)
	except:
		return
	comment = usercn + ":null user_specific_rule"
	for destip in fetch_ips_from_file(fd):
		build_firewall_rule(usersrcip, usersrcip, destip, '', '', comment)
	fd.close()

def load_rules(usersrcip, usercn, dev):
	"""
		First, get the list of VPN groups, with members and IPs, from LDAP.
		Second, find the groups that the user belongs to, and create the rules.
		Third, if per user rules exist, load them
		And finally, insert a DROP rule at the bottom of the ruleset

		Return: A string with the LDAP groups the user belongs to
	"""
	usergroups = ""
	uniq_nets = list()
	schema = load_ldap()
	for group in schema:
		if usercn in schema[group]['cn']:
			networks = schema[group]['networks']
			load_group_rule(usersrcip, usercn, dev, group, networks, uniq_nets)
			usergroups += group + ';'
	load_per_user_rules(usersrcip, usercn, dev)
	return usergroups

def chain_exists(name):
	"""
		Test existance of a chain via the iptables binary
	"""
	return iptables('-L ' + name, False)

def add_chain(usersrcip, usercn, dev):
	"""
		Create a custom chain for the VPN user, named using his source IP
		Load the LDAP rules into the custom chain
		Jump traffic to the custom chain from the INPUT,OUTPUT & FORWARD chains
	"""
	# safe cleanup, just in case
	command = "%s %s" % (RULESCLEANUP, usersrcip)
	status = os.system(command)
	usergroups = ""
	if chain_exists(usersrcip):
		cef('Chain exists|Attempted to replace an existing chain. Failing.',
			'dst=' + usersrcip + ' suser=' + usercn)
		sys.exit(1)
	iptables('-N ' + usersrcip)
	ipset('--create ' + usersrcip + ' nethash')
	usergroups = load_rules(usersrcip, usercn, dev)
	iptables('-A OUTPUT -d ' + usersrcip + ' -j ' + usersrcip)
	iptables('-A INPUT -s ' + usersrcip + ' -j ' + usersrcip)
	iptables('-A FORWARD -s ' + usersrcip + ' -j ' + usersrcip)
	comment = usercn + ' groups: ' + usergroups
	if len(comment) > 254:
		comment = comment[:243] + '..truncated...'
	iptables('-I ' + usersrcip + ' -s ' + usersrcip +
			 ' -m set --match-set ' + usersrcip + ' dst -j ACCEPT' +
			 ' -m comment --comment "' + comment[:254] + '"')
	iptables('-I ' + usersrcip + ' -m conntrack --ctstate ESTABLISHED -j ACCEPT' +
			 ' -m comment --comment "' + usercn + ' at ' + usersrcip + '"')
	iptables('-A ' + usersrcip + ' -j LOG --log-prefix "DROP ' + usercn[:23] +
			 ' "' + ' -m comment --comment "' + usercn + ' at ' + usersrcip + '"')
	iptables('-A ' + usersrcip + ' -j DROP' +
			 ' -m comment --comment "' + usercn + ' at ' + usersrcip + '"')

def del_chain(usersrcip, dev):
	"""
		Delete the custom chain and all associated rules
	"""
	iptables('-D OUTPUT -d ' + usersrcip + ' -j ' + usersrcip, False)
	iptables('-D INPUT -s ' + usersrcip + ' -j ' + usersrcip, False)
	iptables('-D FORWARD -s ' + usersrcip + ' -j ' + usersrcip, False)
	iptables('-F ' + usersrcip, False)
	iptables('-X ' + usersrcip, False)
	ipset("--destroy " + usersrcip, False)
	# safe cleanup, just in case
	command = "%s %s" % (RULESCLEANUP, usersrcip)
	status = os.system(command)

def update_chain(usersrcip, usercn, dev):
	"""
		Wrapper function around add and delete
	"""
	del_chain(usersrcip, dev)
	add_chain(usersrcip, usercn, dev)

def main():
	"""
		Main function, called with 3 arguments
		- 'operation' is either 'add', 'delete' or 'update'
		- 'user src ip' is the source IP address of the VPN user, as allocated
		  by openvpn.
		- 'cn' is the openvpn login that will be queried in LDAP
		these arguments are provided via the 'learn-address' openvpn hook
	"""
	try:
		device = os.environ['dev']
	except:
		device = 'lo'
	try:
		client_ip = os.environ['untrusted_ip']
		client_port = os.environ['untrusted_port']
	except:
		client_ip = '127.0.0.1'
		client_port = '0'

	if len(sys.argv) < 3:
		print("Forgot something, like, arguments?")
		print("USAGE: %s <operation> <user src ip> [cn]" % sys.argv[0])
		sys.exit(1)

	operation = sys.argv[1]
	usersrcip = sys.argv[2]
	if len(sys.argv) == 4:
		usercn = sys.argv[3]
	else:
		usercn = None

	if operation == 'add':
		cef('User Login Successful|OpenVPN endpoint connected',
			'src=' + client_ip + ' spt='+client_port + ' dst=' + usersrcip +
			' suser=' + usercn)
		add_chain(usersrcip, usercn, device)
	elif operation == 'update':
		cef('User Login Successful|OpenVPN endpoint re-connected',
			'src=' + client_ip + ' spt=' + client_port + ' dst=' + usersrcip +
			' suser=' + usercn)
		update_chain(usersrcip, usercn, device)
	elif operation == 'delete':
		cef('User Login Successful|OpenVPN endpoint disconnected',
			'dst=' + usersrcip)
		del_chain(usersrcip, device)
	else:
		log('Unknown operation')
	sys.exit(0)

if __name__ == "__main__":
    main()
