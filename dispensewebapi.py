from flask import Flask, request, Response
from flask.ext.restful import Resource, Api, reqparse
from functools import wraps
import re, ldap, syslog, socket

app = Flask(__name__)
api = Api(app)

authparser = reqparse.RequestParser()
authparser.add_argument('username', type=str)
authparser.add_argument('password', type=str)
def requires_auth(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		auth = request.authorization
		if not auth:
			authargs = authparser.parse_args()
			username = authargs['username']
			password = authargs['password']
			if username is None or password is None:
				return Response('{"status": "error", "errmsg": "Authentication failed"}', 401,
						{'Content-Type': 'application/json', 'WWW-Authenticate': 'Basic'})
		else:
			username = auth.username
			password = auth.password
		username = username.lower()
		expr = re.compile('^[-\w]+$')
		if not expr.match(username):
			return {'status': 'error', 'errmsg': 'Authentication failed: Invalid username'}
		dn = 'uid=%s,ou=People,dc=ucc,dc=gu,dc=uwa,dc=edu,dc=au' % username
		try:
			l = ldap.initialize('ldaps://mussel.ucc.gu.uwa.edu.au')
			l.simple_bind_s(dn, password)
			l.unbind_s()
		except:
			log = 'Authentication failure for user ' + username + ' from ' + request.remote_addr + '\n'
			syslog.syslog((syslog.LOG_NOTICE | syslog.LOG_AUTH), log)
			return {'status': 'error', 'errmsg': 'Authetication failed: Username or password is incorrect'}
		kwargs['username'] = username
		return f(*args, **kwargs)
	return decorated

DISP_SERVER = ('merlo.ucc.asn.au',11020)
def dispcmd(commands):
	output = []
	if not isinstance(commands, list): commands = [commands]
	s = socket.socket()
	s.connect(DISP_SERVER)
	f = s.makefile()
	for command in commands:
		if command[-1] != '\n': command += '\n'
		s.send(command)
	for command in commands:
		output.append(f.readline())
		cmd = command.split()[0]
		if output[-1].startswith('4') or output[-1].startswith('5'):
			raise ValueError(output[-1])
		if output[-1].startswith('201'):
			lines = int(output[-1].split()[-1])
			while not output[-1][0:3].startswith('200') and lines >= 0:
				output.append(f.readline())
				lines -= 1
	f.close()
	s.close()
	return output

class users(Resource):
	def get(self, username=None):
		try:
			if username is None:
				output = dispcmd('ENUM_USERS')
			else:
				expr = re.compile('^[-\w]+$')
				if not expr.match(username):
					return {'status': 'error', 'errmsg': 'Invalid username'}
				output = dispcmd('USER_INFO ' + username)
		except ValueError,e:
			return {'status': 'error', 'errnum': int(str(e).split()[0]), 'errmsg': str(e)}
		users = {}
		for line in output:
			if not line.startswith('202 User'): continue
			line = line.split()
			uname = line[2]
			balance = int(line[3])
			flags = {}
			for flag in ['user', 'coke', 'admin', 'internal', 'disabled', 'door']:
				if flag in line[-1].split(','): flags[flag] = True
				else: flags[flag] = False
			users[uname] = {'balance': balance, 'flags': flags}
		return {'status': 'success', 'users': users}
api.add_resource(users, '/users', '/users/<string:username>')

class query(Resource):
	def get(self, itemtype=None, slot=None):
		items = {}
		if itemtype is None or itemtype == 'door':
			items['door'] = {0: {'name': 'door', 'price': 0, 'available': True}}
		if itemtype != 'door':
			try:
				if slot is None: lines = dispcmd('ENUM_ITEMS')
				else: lines = dispcmd('ITEM_INFO ' + itemtype + ':' + str(slot))
			except ValueError,e:
				return {'status': 'error', 'errnum': int(str(e).split()[0]), 'errmsg': str(e)}
			for line in lines:
				if not line.startswith('202 Item'): continue
				line = line.split()
				lname = ' '.join(line[5:])
				ltype = line[2].split(':')[0]
				lslot = int(line[2].split(':')[1])
				lavail = line[3] == 'avail'
				if itemtype is not None and ltype != itemtype: continue
				if ltype not in items: items[ltype] = {}
				items[ltype][lslot] = {'name': lname, 'price': int(line[4]), 'available': lavail}
		if itemtype is not None and itemtype not in items: return {'status': 'error', 'errmsg': 'Unknown item type'}
		return {'status': 'success', 'items': items}
api.add_resource(query, '/items', '/items/<string:itemtype>', '/items/<string:itemtype>/<int:slot>')

class dispense(Resource):
	@requires_auth
	def post(self, itemtype, slot, **kwargs):
		username = kwargs['username']
		commands = [	'AUTHIDENT',
				'SETEUSER ' + username,
				'DISPENSE ' + itemtype + ':' + str(slot)	]
		try:
			output = dispcmd(commands)
		except ValueError,e:
			return {'status': 'error', 'errnum': int(str(e).split()[0]), 'errmsg': str(e)}
		return {'status': 'success'}
api.add_resource(dispense, '/items/<string:itemtype>/<int:slot>/dispense')
