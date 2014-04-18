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
# jvehent@mozilla.com (ipset support)
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
import fcntl
import time
import signal, errno
import mozdef
from contextlib import contextmanager
import imp

cfg_path = ['netfilter_openvpn.conf', '/etc/openvpn/netfilter_openvpn.conf', '/etc/netfilter_openvpn.conf']
config = None

for cfg in cfg_path:
	try:
		config = imp.load_source('config', cfg)
	except:
		pass

if config == None:
	print("Failed to load config")
	sys.exit(1)

#MozDef Logging
mdmsg = mozdef.MozDefMsg(MOZDEF_HOST, tags=['openvpn', 'netfilter'])

@contextmanager
def lock_timeout(seconds):
	def timeout_handler(signum, frame):
		pass
	original_handler = signal.signal(signal.SIGALRM, timeout_handler)
	try:
		signal.alarm(seconds)
		yield
	finally:
		signal.alarm(0)
		signal.signal(signal.SIGALRM, original_handler)

def wait_for_lock():
	acquired = False
	retries = 0
	while not acquired:
		with lock_timeout(config.LOCKWAITTIME):
			if retries >= config.LOCKRETRIESMAX:
				return None
			try:
				lockfd = open(config.LOCKPATH, 'a+')
				fcntl.flock(lockfd, fcntl.LOCK_EX)
			except (IOError, OSError) as e:
				mdmsg.send(summary='Failed to aquire lock.',
					details={"lock_path": config.LOCKPATH, "error": e.errno, "lock_retry_seconds": config.LOCKWAITTIME})
			else:
				acquired = True
			retries += 1
	return lockfd

def free_lock(lockfd):
	fcntl.flock(lockfd, fcntl.LOCK_UN)
	lockfd.close()
	return

class IptablesFailure (Exception):
	pass

def iptables(args, raiseEx=True):
	"""
		Load the firewall rule received as argument on the local system, using
		the iptables binary

		Return: True on success, Exception on error if raiseEX=True
				False on error if raiseEx=False
	"""
	command = "%s %s" % (config.IPTABLES, args)
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
	command = "%s %s" % (config.IPSET, args)
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
	conn = ldap.initialize(config.LDAP_URL)
	conn.simple_bind_s(config.LDAP_BIND_DN, config.LDAP_BIND_PASSWD)
	res = conn.search_s(config.LDAP_BASE_DN, ldap.SCOPE_SUBTREE, config.LDAP_FILTER,
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
				mdmsg.send(summary='Failed to load user from LDAP', details={'user': u, 'group': group})
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
		rule_file = config.RULES + "/" + group + '.rules'
		try:
			fd = open(rule_file)
		except:
			# Skip if file is not found
			mdmsg.send(summary="Failed to open rule file, skipping group", details={'rule_file': rule_file, 'user': usercn})
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
	rule_file = config.RULES + "/" + config.PER_USER_RULES_PREFIX + usercn
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
	command = "%s %s" % (config.RULESCLEANUP, usersrcip)
	status = os.system(command)
	usergroups = ""
	if chain_exists(usersrcip):
		mdmsg.send(summary='Attempted to replace an existing chain, failing.',
			details={'srcip': usersrcip, 'user': usercn})
		return False
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
	return True

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
	command = "%s %s" % (config.RULESCLEANUP, usersrcip)
	status = os.system(command)

def update_chain(usersrcip, usercn, dev):
	"""
		Wrapper function around add and delete
	"""
	del_chain(usersrcip, dev)
	return add_chain(usersrcip, usercn, dev)

def main():
	device = os.environ.get('dev', 'lo')
	client_ip = os.environ.get('untrusted_ip', '127.0.0.1')
	client_port = os.environ.get('untrusted_port', '0')
	usercn = os.environ.get('common_name', None)
	if usercn == None:
		usercn = os.environ.get('username', None)

	if len(sys.argv) < 2:
		printf("USAGE: %s <operation>" % sys.argv[0])
		return False
	operation = sys.argv[1]

	if operation == 'add':
		mdmsg.send(summary='Logging success: OpenVPN endpoint connected',
			details={'srcip': client_ip, 'srcport': client_port, 'user': usercn})
		return add_chain(client_ip, usercn, device)
	elif operation == 'update':
		mdmsg.send(summary='Logging success: OpenVPN endpoint re-connected',
			details={'srcip': client_ip, 'srcport': client_port, 'user': usercn})
		return update_chain(client_ip, usercn, device)
	elif operation == 'delete':
		mdmsg.send(summary='Logout success: OpenVPN endpoint disconnected',
			details={'srcip': client_ip, 'srcport': client_port, 'user': usercn})
		del_chain(client_ip, device)
	else:
		mdmsg.send(summary='Logging success: OpenVPN unknown operation',
			details={'srcip': client_ip, 'srcport': client_port, 'user': usercn})
	return True

def exit(status):
	""" Note that status is 0 for success (program return code), while ctrl_txt is 1 for success (openvpn control file
		return code) """

	control = os.environ.get('auth_control_file')
	if control == None:
		mdmsg.send(summary='No control file found, if using deferred plugin call the authentication will stall and
		fail.', details={'srcip': client_ip, 'srcport': client_port, 'user': usercn})

	ctrl_txt = '0' # failure by default

	if status == 0:
		ctrl_txt = '1'

	try:
		with open(control, 'w') as f:
			f.write(ctrl_txt)
	except:
		pass
	sys.exit(status)

if __name__ == "__main__":
#	we only authorize one script execution at a time
	lockfd = wait_for_lock()
	if (lockfd == None):
		exit(1)

	if main():
		free_lock(lockfd)
		exit(0)

	free_lock(lockfd)
	exit(1)
