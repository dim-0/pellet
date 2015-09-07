#!/usr/bin/env python
# 
# pellet.py - TCP lookup table for Postfix smtpd_sender_maps 
#
# This python script will act as a tcp lookup table for postfix
# in order to provide enhanced LDAP support
#
# To integrate with postfix add following lines
#
# - to master.cf:
#
#  127.0.0.1:<port> inet  n       n       n       -       0      spawn
#    user=<user> argv=/path/to/pellet.py
#
# - to main.cf:
#
#  smtpd_sender_login_maps = tcp:[127.0.0.1]:<port>
#  127.0.0.1:<port>_time_limit = 3600s

import sys, os, configparser, ldap, re


### Constants
CONFIG_FILE = './pellet.conf'
MAX_RESP_LEN = 4091 # Max. response length = 4096 - 3 (return code) - 1 (space) - 1 (new line)

RCODES = [200, 400, 500]
SCHEMES = ['ldap', 'ldaps', 'ldapi']
DEREFS = ['never', 'search', 'find', 'always']
SCOPES = ['base', 'one', 'sub']
DOMAIN_BYS = ['dn', 'memberof', 'fixed']
NON_DPARTS = ['break', 'skip']
GET_ALIASED = ['on', 'off']

### Functions
# Output
def output(rc, msg):
	if rc in RCODES:
		if len(msg) > MAX_RESP_LEN:
			msg = msg[0:MAX_RESP_LEN]
		print(str(rc) + ' ' + msg)
	else:
		raise Exception('Invalid return code', rc)

# Format result
def format_result(inp):
	result = ''
	for addr in inp:
		if len(result) == 0:
			result = addr
		else:
			result = result + ' ' + addr
	return (result)

# Format LDAP DN to domain
def retrieve_domain(dn):
	found       = False
	domain      = ''
	attr_domain = config['result'].get('attr_domain', 'dc')
	non_dpart   = config['result'].get('non_dpart', 'break')

	dn_parts = dn.split(',')

	for dn_part in dn_parts:
		if dn_part.startswith(attr_domain + '='):
			found = True
			dpart = dn_part.lstrip(attr_domain + '=').lower()
			if not domain:
				domain = dpart
			else:
				domain = domain + '.' + dpart
		elif found and non_dpart == 'break':
			break

	return (domain)

# Format LDAP entries to e-mail addresses
def retrieve_addrs(res):
	addrs = []

	attr_local   = config['result'].get('attr_local', 'uid')
	domain_by    = config['result'].get('domain_by', 'dn')
	domain_fixed = config['result'].get('domain_fixed')

	for entry in res:
		dn = entry[0]
		attrs = entry[1]

		for local in attrs[attr_local]:
			if domain_by == 'dn':
				domain = retrieve_domain(dn)
				if domain:
					addr = local + '@' + domain
					if not addr in addrs:
						addrs.append(addr)
			elif domain_by == 'memberof' and 'memberOf' in attrs:
				for memberof in attrs["memberOf"]:
					domain = retrieve_domain(memberof)
					if domain:
						addr = local + '@' + domain
						if not addr in addrs:
							addrs.append(addr)
			elif domain_by == 'fixed':
				addr = local + '@' + domain_fixed
				if not addr in addrs:
					addrs.append(addr)

	return (addrs)

# Adjust base dn/filter
def adjust(inp, sender, user, dom, dom_p):
	inp = inp.replace('%n', sender)
	inp = inp.replace('%u', user)

	for i in range(0,len(dom_p)-1):
		rs = '%d' + str(i)
		inp = inp.replace(rs, dom_p[i])

	inp = inp.replace('%d', dom)
	inp = inp.replace('%%', '%')
	return (inp)

# Search LDAP
def ldap_search(uri, bind_dn, bind_pw, base, ldap_filter, scope, deref, attrs):
	print uri
	print bind_dn
	print bind_pw
	print base
	print ldap_filter
	print scope
	print deref
	print attrs

	lc = ldap.initialize(uri)

	if bind_dn:
                lc.simple_bind_s(bind_dn, bind_pw)

	if scope == 'base':
                scope = ldap.SCOPE_BASE
        elif scope == 'one':
                scope = ldap.SCOPE_ONELEVEL
        elif scope == 'sub':
                scope = ldap.SCOPE_SUBTREE

        if deref == 'search':
                lc.set_option(ldap.OPT_DEREF, 1)
        elif deref == 'find':
                lc.set_option(ldap.OPT_DEREF, 2)
        elif deref == 'always':
                lc.set_option(ldap.OPT_DEREF, 3)
        else:
                lc.set_option(ldap.OPT_DEREF, 0)

        entries = lc.search_s(base, scope, ldap_filter, attrs)

        lc.unbind_s()

	return (entries)

# Get connected addresses
def get_sasls(sender):
	entries = []

	addr_parts = sender.split('@', 1)
	user       = addr_parts[0] # local part
	domain     = addr_parts[1] # domain part
	domain_p   = domain.split('.') # exploded domain

        scheme       = config['ldap'].get('scheme', 'ldap')
        server       = config['ldap'].get('server', '127.0.0.1')
        port         = config['ldap'].get('port', '389')

        bind_dn      = config['bind'].get('dn')
        bind_pw      = config['bind'].get('pw')

        base         = config['query'].get('base')
        ldap_filter  = config['query'].get('filter', '(objectClass=*)')
	scope        = config['query'].get('scope', 'base')
        deref        = config['query'].get('deref', 'never')
        attrs        = config['query'].get('attrs').encode('ascii', 'ignore').split()

	get_aliased  = config['alias'].get('get_aliased', 'off')
	alias_filter = config['alias'].get('alias_filter', '(objectClass=*)')

        uri = scheme + '://' + server + ':' + port
	base = adjust(base, sender, user, domain, domain_p)

	if ldap_filter:
		ldap_filter = adjust(ldap_filter, sender, user, domain, domain_p)

        objects = ldap_search(uri, bind_dn, bind_pw, base, ldap_filter, scope, deref, attrs)

	for object in objects:
		dn = object[0]
		values = object[1]
		if get_aliased == 'on' and 'objectClass' in values and 'alias' in values['objectClass']:
			dobjects = ldap_search(uri, bind_dn, bind_pw, dn, alias_filter, 'base', 'always', attrs)
			for dobject in dobjects:
				entries.append(dobject)
		else:
			entries.append(object)

	return (retrieve_addrs(entries))

# Get parameters
def parse(request):
	if request.startswith('get '):
		payload = request.lstrip('get ').lower()
		return (payload)
	else:
		raise Exception('Malformed request data', request)

# Check mandatory config options
def check_mandatory_options():
	if not config['query'].get('base'):
		raise Exception('Configuration parameter is missing', '[query] base')
	if config['result'].get('domain_by') == 'fixed' and not config['result'].get('domain_fixed'):
		raise Exception('Configuration parameter is missing', '[result] domain_fixed')

# Check valid config options
def check_valid_options():
	if config['ldap'].get('scheme', 'ldap') not in SCHEMES:
		raise Exception('Invalid value for config option', '[ldap] scheme')
	if config['query'].get('deref', 'never') not in DEREFS:
		raise Exception('Invalid value for config option', '[query] deref')
	if config['query'].get('scope', 'base') not in SCOPES:
		raise Exception('Invalid value for config option', '[query] scope')
	if config['result'].get('domain_by', 'dn') not in DOMAIN_BYS:
		raise Exception('Invalid value for config option', '[result] domain_by')
	if config['result'].get('non_dparts', 'break') not in NON_DPARTS:
		raise Exception('Invalid value for config option', '[result] non_dpart')
	if config['alias'].get('get_aliased', 'off') not in GET_ALIASED:
		raise Exception('Invalid value for config option', '[alias] get_aliased')

# Read config
def read_config():
	global config

	config = configparser.ConfigParser(interpolation=None)
	config.read_file(open(CONFIG_FILE))
	check_mandatory_options()
	check_valid_options()

# Initialization
def initialize():
	# Auto-flush the output stream
	sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

	read_config()


### Execution
initialize()

while True:
	try:
		sender = parse(raw_input())

		if not re.match(r'[^@]+@[^@]+\.[^@]+', sender):
			output(500, 'Not a valid e-mail address')
		else:
			result = get_sasls(sender)

			if result:
				output(200, format_result(result))
			else:
				output(500, 'Could not match address')
	except Exception as exc:
		msg = exc.args
		print('400 Error: ' + str(msg[0]) + ' ' + str(msg[1]))
