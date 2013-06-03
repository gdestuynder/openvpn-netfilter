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
RULES='<%= confdir %>/plugins/netfilter/rules'
PER_USER_RULES_PREFIX='users/vpn_'

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
#	log(cefmsg)

class IptablesFailure (Exception):
	pass

def iptables(args, raiseEx=True):
	"""False on error if raiseEx=True, True on success, Exception otherwise"""
	command = "%s %s" % (IPTABLES, args)
	status = os.system(command)
	if status == -1:
		raise IptablesFailure("failed to invoke iptables (%s)" % (command,))
	status = os.WEXITSTATUS(status)
	if raiseEx and (status != 0):
		raise IptablesFailure("iptables exited with status %d (%s)" % (status, command))
	if (status != 0):
		return False
	return True

def log(msg):
	syslog.openlog('OpenVPN', 0, syslog.LOG_DAEMON)
	syslog.syslog(syslog.LOG_INFO, msg)
	syslog.closelog()

def cef(msg1, msg2):
	syslog.openlog('OpenVPN', 0, CEF_FACILITY)
	cefmsg = 'CEF:0|Mozilla|OpenVPN|1.0||'+msg1+'|5|'+msg2+' dhost='+NODENAME
	syslog.syslog(syslog.LOG_INFO, cefmsg)
	syslog.closelog()
#	log(cefmsg)

def parse_rules(fd):
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
	conn = ldap.initialize(LDAP_URL)
	conn.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWD)
	res = conn.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, LDAP_FILTER, ['cn', 'member', 'ipHostNumber'])
#schema = {'vpn_example1': {'cn': ['noob1@mozilla.com', 'noob2@mozilla.com'],
#'networks': ['192.168.0.1/24', '10.0.0.1/16:80 #comment', '10.0.0.1:22']}, 'vpn_example2': ...}
	schema = {}
	for grp in res:
		ulist = []
		hlist = []
		group = grp[1]['cn'][0]

		for u in grp[1]['member']:
			try:
				ulist.append(u.split('=')[1].split(',')[0])
			except:
				log("Failed to load user from LDAP: %s at group %s, skipping" % (u, group))
		if grp[1].has_key('ipHostNumber'):
			hlist = grp[1]['ipHostNumber']
		schema[group] = {'cn': ulist, 'networks': hlist}
	return schema

def load_group_rule(address, cn, dev, group, networks):
	#Some of the parsing is hackish (accomodating the ever-changing hack to have attributes inside an attribute in LDAP)
	#this probably needs some refactoring when we're happy with the rule format
	if len(networks) != 0:
		for net in networks:
			#the attribute stored in net (ipHostNumber) includes 2 values, address/network and a comment string
			tmp = net.split("#")
			neta = tmp[0] #address/network/port
			netc = ""
			if len(tmp) >= 2:
				netc = tmp[1] #comment
			tmp = neta.split(':')
			#split address:port into neta (address/network) and netp (port), if we have some. (: sep)
			if len(tmp) >= 2:
				neta = tmp[0]
				netp = tmp[1]
				iptables("-A %s -s %s -d %s -p tcp -m multiport --dports %s -j ACCEPT -m comment --comment \"%s:%s ldap_acl %s\"" % (address, address, neta, netp, cn, group, netc))
				iptables("-A %s -s %s -d %s -p udp -m multiport --dports %s -j ACCEPT -m comment --comment \"%s:%s ldap_acl %s\"" % (address, address, neta, netp, cn, group, netc))
			else:
				iptables("-A %s -s %s -d %s -j ACCEPT -m comment --comment \"%s:%s ldap_acl %s\"" % (address, address, neta, cn, group, netc))
				iptables("-A %s -d %s -s %s -j ACCEPT -m comment --comment \"%s:%s ldap_acl %s\"" % (address, address, neta, cn, group, netc))
	else:
		rule_file = RULES+"/"+group+'.rules'
		try:
			fd = open(rule_file)
		except:
			#if there's no LDAP ACL loaded, and there's no file loaded, complain and skip
			log("Failed to open rule file %s for user %s, skipping group" % (rule_file, cn))
			return

		for r in parse_rules(fd):
			iptables("-A %s -s %s -d %s -j ACCEPT -m comment --comment \"%s:%s file_acl\"" %  (address, address, r, cn, group))
			iptables("-A %s -d %s -s %s -j ACCEPT -m comment --comment \"%s:%s file_acl\"" %  (address, address, r, cn, group))
		fd.close()

def load_rules(address, cn, dev):
	schema = load_ldap()
	for group in schema:
		if cn in schema[group]['cn']:
			networks = schema[group]['networks']
			load_group_rule(address, cn, dev, group, networks)
	load_per_user_rules(address, cn, dev)
	iptables("-A %s -j DROP" % (address))

def load_per_user_rules(address, cn, dev):
	rule_file = RULES+"/"+PER_USER_RULES_PREFIX+cn
	try:
		fd = open(rule_file)
	except:
# by default, there's generally no per user rules, so fail in silence
		return

	for r in parse_rules(fd):
		iptables("-A %s -s %s -d %s -j ACCEPT -m comment --comment \"%s:null user_specific_rule\"" % (address, address, r, cn))
	fd.close()

def chain_exists(name):
	return iptables('-L '+name, False)

def add_chain(address, cn, dev):
	if chain_exists(address):
		cef('Chain exists|Attempted to replace an existing chain. Failing.', 'dst='+address+' suser='+cn)
		sys.exit(1)
	iptables('-N '+address)
	iptables('-A OUTPUT -d '+address+' -j '+address)
	iptables('-A INPUT -s '+address+' -j '+address)
	iptables('-A FORWARD -s '+address+' -j '+address)
	load_rules(address, cn, dev)

def update_chain(address, cn, dev):
	del_chain(address, dev)
	add_chain(address, dev)
	
def del_chain(address, dev):
	iptables('-D OUTPUT -d '+address+' -j '+address, False)
	iptables('-D INPUT -s '+address+' -j '+address, False)
	iptables('-D FORWARD -s '+address+' -j '+address, False)
	iptables('-F '+address, False)
	iptables('-X '+address, False)

def main():
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
		print("USAGE: %s <operation> <address> [cn]" % sys.argv[0])
		sys.exit(1)

	operation = sys.argv[1]
	address = sys.argv[2]
	if len(sys.argv) == 4:
		cn = sys.argv[3]
	else:
		cn = None

	if operation == 'add':
		cef('User Login Successful|OpenVPN endpoint connected', 'src='+client_ip+' spt='+client_port+' dst='+address+' suser='+cn)
		add_chain(address, cn, device)
	elif operation == 'update':
		cef('User Login Successful|OpenVPN endpoint re-connected', 'src='+client_ip+' spt='+client_port+' dst='+address+' suser='+cn)
		update_chain(address, cn, device)
	elif operation == 'delete':
		cef('User Login Successful|OpenVPN endpoint disconnected', 'dst='+address)
		del_chain(address, device)
	else:
		log('Unknown operation')
	sys.exit(0)

if __name__ == "__main__":
    main()
