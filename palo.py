import json
import requests
# python3 -m pip install requests[socks]
requests.packages.urllib3.disable_warnings()
import xml.etree.ElementTree as et
import time

def timestamp(method):
	def wrapper(*args, **kwargs):
		ts = time.time()
		result = method(*args, **kwargs)
		te = time.time()
		time_result = int((te-ts) * 1000)
		message = (
			f'[I] '
			f'{method.__qualname__}'
			f' took '
			f'{time_result}'
			f'ms to complete, or ~'
			f'{time_result//60000}'
			'm, or ~'
			f'{time_result//1000}'
			f's'
		)
		print(message)
		return result
	return wrapper

class PaloAlto(object):
	version = '9.0'
	def __init__(self, hostname):
		self.load_credentials(hostname)
		self.session = requests.Session()
		self.hostname = hostname
		self.base_url = f'https://{hostname}'
		#proxies = {
		#	'http': 'socks5h://127.0.0.1:1080',
		#	'https': 'socks5h://127.0.0.1:1080',
		#}
		#self.session.headers.update()
		#self.session.proxies = proxies
		return
	
	def load_credentials(self, hostname):
		'''
			keys = ['username','password']
		'''
		try:
			open('configuration.json','r')
		except:
			print('[E] Credentials not found')
		
		with open('configuration.json','r') as f:
			file_raw = f.read()
		credentials = json.loads(file_raw)
		self.un = credentials['credentials'][hostname]['username']
		self.pw = credentials['credentials'][hostname]['password']
		self.token = credentials['credentials'][hostname]['token']
		return
	
	def get_token(self):
		import xml.etree.ElementTree as ET
		if self.token:
			output = {
				'success': True,
				'result': self.token,
				'response': '',
			}
			return output
		url = f'{self.base_url}/api/?type=keygen&user=<username>&password=<password>'
		params = {
			'type': 'keygen',
			'user': self.un,
			'password': self.pw,
		}
		response = self.session.get(
			url,
			params=params,
			verify=False,
		)
		output = {
			'success': False,
			'result': response.text,
			'response': response,
		}
		if response.status_code == 200:
			output['success'] = True
			try:
				response_xml = ET.fromstring(
					response.text
				)
				output['result'] = response_xml
			except:
				pass
		return output
	
	def login(self):
		output = self.get_token()
		if not self.token:
			self.token = output['result'][0][0].text
			# write to configuration.json
			with open('configuration.json','r') as f:
				file_raw = f.read()
			credentials = json.loads(file_raw)
			if hostname not in credentials['credentials']:
				credentials['credentials'][hostname] = {
					'username': '',
					'password': '',
					'token': self.token,
				}
				with open('configuration.json','w') as f:
					f.write(
						json.dumps(credentials)
					)
		headers = {
			'X-PAN-KEY': self.token,
		}
		self.session.headers.update(headers)
		return output
	
	##
	## Basic HTTP Handling
	
	def get(self, path, params={}):
		url = f'{self.base_url}/restapi/{self.version}/{path}'
		_params = {
			'location': 'vsys',
			'vsys': 'vsys1',
		}
		for param_key in params:
			_params[param_key] = params[param_key]
		response = self.session.get(
			url,
			params=_params,
			verify=False,
		)
		output = {
			'success': False,
			'result': response.text,
			'response': response,
		}
		if response.status_code == 200:
			output['success'] = True
			try:
				response_json = json.loads(
					response.text
				)
				output['result'] = response_json
			except:
				print('could not load JSON')
				pass
		elif response.status_code == 401:
			self.login()
			response = self.session.get(
				url,
				params=params,
				verify=False,
			)
			if response.status_code == 200:
				output['success'] = True
				try:
					response_json = json.loads(
						response.text
					)
					output['result'] = response_json
				except:
					pass
		return output
	
	def post(self, path, body={}, params={}):
		url = f'{self.base_url}/restapi/{self.version}/{path}'
		_params = {
			'location': 'vsys',
			'vsys': 'vsys1',
		}
		for param_key in params:
			_params[param_key] = params[param_key]
		response = self.session.post(
			url,
			jason=body,
			params=_params,
			verify=False,
		)
		output = {
			'success': False,
			'result': response.text,
			'response': response,
		}
		if response.status_code == 200:
			output['success'] = True
			try:
				response_json = json.loads(
					response.text
				)
				output['result'] = response_json
			except:
				print('could not load JSON')
				pass
		elif response.status_code == 401:
			self.login()
			response = self.session.post(
				url,
				json=body,
				params=params,
				verify=False,
			)
			if response.status_code == 200:
				output['success'] = True
				try:
					response_json = json.loads(
						response.text
					)
					output['result'] = response_json
				except:
					pass
		return output
	
	def put(self, path, body={}, params={}):
		url = f'{self.base_url}/restapi/{self.version}/{path}'
		_params = {
			'location': 'vsys',
			'vsys': 'vsys1',
		}
		for param_key in params:
			_params[param_key] = params[param_key]
		response = self.session.put(
			url,
			jason=body,
			params=_params,
			verify=False,
		)
		output = {
			'success': False,
			'result': response.text,
			'response': response,
		}
		if response.status_code == 200:
			output['success'] = True
			try:
				response_json = json.loads(
					response.text
				)
				output['result'] = response_json
			except:
				print('could not load JSON')
				pass
		elif response.status_code == 401:
			self.login()
			response = self.session.put(
				url,
				json=body,
				params=params,
				verify=False,
			)
			if response.status_code == 200:
				output['success'] = True
				try:
					response_json = json.loads(
						response.text
					)
					output['result'] = response_json
				except:
					pass
		return output
	
	def delete(self, path, params={}):
		url = f'{self.base_url}/restapi/{self.version}/{path}'
		_params = {
			'location': 'vsys',
			'vsys': 'vsys1',
		}
		for param_key in params:
			_params[param_key] = params[param_key]
		response = self.session.delete(
			url,
			params=_params,
			verify=False,
		)
		output = {
			'success': False,
			'result': response.text,
			'response': response,
		}
		if response.status_code == 200:
			output['success'] = True
			try:
				response_json = json.loads(
					response.text
				)
				output['result'] = response_json
			except:
				print('could not load JSON')
				pass
		elif response.status_code == 401:
			self.login()
			response = self.session.delete(
				url,
				params=params,
				verify=False,
			)
			if response.status_code == 200:
				output['success'] = True
				try:
					response_json = json.loads(
						response.text
					)
					output['result'] = response_json
				except:
					pass
		return output
	
	##
	## REST Functions
	
	def get_object_list(self):
		path = '/Objects/Addresses'
		params = {
			'location': 'vsys',
			'vsys': 'vsys1',
		}
		output = self.get(path, params=params)
		return output
	
	def get_policy_list(self):
		path = '/Policies/SecurityRules'
		params = {
			'location': 'vsys',
			'vsys': 'vsys1',
		}
		output = self.get(path, params=params)
		return output
	
	def get_vsys_list(self):
		path = '/Device/VirtualSystems'
		params = {
			'location': 'vsys',
			'vsys': 'vsys1',
		}
		output = self.get(path, params=params)
		return output
	
	def add_rule(self, name):
		path = '/Policies/SecurityRules'
		params = {
			'name': name,
		}
		data = {
			'entry': {
				'@name': name,
				'from': {'member': ['any']},
				'to': {'member': ['any']},
				'source': {'member': ['any']},
				'destination': {'member': ['any']},
				'service': {'member': ['any']},
				'application': {'member': ['any']},
				'action': 'allow',
				'disabled': 'yes',
			}
		}
		output = self.post(
			path,
			body=data,
			params=params,
		)
		return output
	
	def edit_rule(self, name):
		path = '/Policies/SecurityRules'
		params = {
			'name': name,
		}
		data = {
			'entry': {
				'@name': name,
				'from': {'member': ['any']},
				'to': {'member': ['any']},
				'source': {'member': ['22.22.22.22','11.11.11.11']},
				'destination': {'member': ['any']},
				'service': {'member': ['any']},
				'application': {'member': ['any']},
				'action': 'allow',
				'disabled': 'yes',
			}
		}
		output = self.put(
			path,
			body=data,
			params=params,
		)
		return output
	
	def delete_rule(self, name):
		path = '/Policies/SecurityRules'
		params = {
			'name': name,
		}
		output = self.delete(path, params=params)
		return output
	
	def get_rule(self, name):
		path = '/Policies/SecurityRules'
		params = {
			'name': name,
		}
		output = self.get(path, params=params)
		return output
	
	def add_member_to_rule(self, name, source_destination, member):
		rule = self.get_rule(name)
		entry = rule['result']['result']['entry'][0]
		if member not in entry[source_destination]['member']:
			entry[source_destination]['member'].append(member)
		else:
			print(member,'already exists in rule')
			return
		data = {
			'entry': entry
		}
		path = '/Policies/SecurityRules'
		params = {
			'name': name,
		}
		output = self.put(
			path,
			body=data,
			params=params,
		)
		return output
	
	##
	## XML Functions
	
	def get_xml(self, get_type, action, xpath='', element=''):
		url = f'{self.base_url}/api/'
		params = {
			'type': get_type,
			'action': action,
			'xpath': xpath,
		}
		if element:
			params['element'] = element
		xml_headers = {
			'Content-Type':	'application/xml',
		}
		response = self.session.get(
			url,
			params=params,
			headers=xml_headers,
			verify=False,
		)
		output = {
			'success': False,
			'result': response.text,
			'response': response,
		}
		if response.status_code == 200:
			output['success'] = True
			output['result'] = response.text
		elif response.status_code == 401:
			self.login()
			response = self.session.get(
				url,
				params=params,
				verify=False,
			)
			if response.status_code == 200:
				output['success'] = True
				output['result'] = response.text
		return output
	
	def xml_to_dict(self, response_raw):
		xml_raw = et.fromstring(response_raw)
		output = self.parse_xml(xml_raw)
		return output
	
	def parse_xml(self, xml_raw):
		print(xml_raw.tag,list(xml_raw))
		output = {'tag': xml_raw.tag, 'text': xml_raw.text, 'attrib': xml_raw.attrib, 'children': [],}
		if len(xml_raw) > 0:
			for xx in xml_raw:
				output['children'].append(self.parse_xml(xx))
		return output

	def create_xml_payload(self, key, data):
		payload_list = [
			f'<{key}>{data[key]}</{key}>'
			for key in data
		]
		payload = ''.join(payload_list)
		output = (
			f'<entry name="{key}">'
			f'{payload}'
			f'</entry>'
		)
		return output
	
	def get_xml_inner(self, key, value, name=''):
		if not name:
			output = (
				f'<{key}>{value}</{key}>'
			)
		else:
			output = (
				f'<{key} name="{name}">{value}</{key}>'
			)
		return output
	
	##
	## XML API Functions
	
	def get_xml_config(self, xpath):
		output = self.get_xml(
			'config',
			'get',
			xpath = xpath,
			element = '',
		)
		return output
	
	def set_xml_config(self, xpath, element):
		method = 'set'
		output = self.get_xml(
			'config',
			'set',
			xpath = xpath,
			element = element,
		)
		return output
	
	def create_zone(self, name):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/zone'
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_policy(self, name):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules'
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_ipsec(self, name):
		xpath = "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_ike_crypto(self, name):
		xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_ike_gateway(self, name):
		xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_ipsec_crypto(self, name):
		xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_tunnel_interface(self, number, comment):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/network/interface/tunnel/units'
		element = self.get_xml_inner('entry', f'<comment>{comment}</comment>', name=f'tunnel.{number}')
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_nat(self, name):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules'
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_object(self, name):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/address'
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def create_object_group(self, name):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/address-group'
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def _create(self, name):
		xpath = ''
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_gateway_peer(self, name, peer):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="{name}"]/peer-address'
		element = self.get_xml_inner('ip',peer)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_gateway_interface(self, name, interface='ae4.974'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="{name}"]/local-address'
		element = p.get_xml_inner('interface', interface)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_gateway_ip(self, name, ip=''):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="{name}"]/local-address'
		element = self.get_xml_inner('ip', ip)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_gateway_nat(self, name, enable='yes'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="{name}"]/protocol-common/nat-traversal'
		element = self.get_xml_inner('enable', enable)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_gateway_crypto_profile(self, name, profile):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="{name}"]/protocol/ikev1'
		element = self.get_xml_inner('ike-crypto-profile', profile)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_gateway_psk(self, name, psk):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="{name}"]/authentication/pre-shared-key'
		element = self.get_xml_inner('key',psk)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_crypto_group(self, name, group='group5'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name="{name}"]/dh-group'
		element = self.get_xml_inner('member',group)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_crypto_encryption(self, name, encryption='aes-256-cbc'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name="{name}"]/encryption'
		element = self.get_xml_inner('member',encryption)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_crypto_hash(self, name, hash='sha1'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name="{name}"]/hash'
		element = self.get_xml_inner('member',hash)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ike_crypto_lifetime(self, name, lifetime='8'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name="{name}"]/lifetime'
		element = self.get_xml_inner('hours', lifetime)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_gateway(self, name, profile):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/tunnel/ipsec/entry[@name="{name}"]/auto-key/ike-gateway'
		element = self.get_xml_inner('entry', '', name=profile)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_profile(self, name, profile):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/tunnel/ipsec/entry[@name="{name}"]/auto-key'
		element = self.get_xml_inner('ipsec-crypto-profile', profile)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_protocol(self, name, protocol='ESP'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name="{name}"]/ah/authentication'
		element = self.get_xml_inner('member', protocol)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_group(self, name, group='group5'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name="{name}"]'
		element = self.get_xml_inner('dh-group', group)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_encryption(self, name, encryption='aes-256-cbc'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name="{name}"]/esp/encryption'
		element = self.get_xml_inner('member', encryption)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_hash(self, name, hash='sha1'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name="{name}"]/esp/authentication'
		element = self.get_xml_inner('member', hash)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_lifetime(self, name, lifetime='1'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name="{name}"]/lifetime'
		element = self.get_xml_inner('hours', lifetime)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_crypto_tunnel(self, name, number):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/tunnel/ipsec/entry[@name="{name}"]'
		element = self.get_xml_inner('tunnel-interface', f'tunnel.{number}')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_zone_source(self, name, source):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/from'
		element = self.get_xml_inner('member', source)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_zone_destination(self, name, destination):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/to'
		element = self.get_xml_inner('member', destination)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_service(self, name, service='any'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/service'
		element = self.get_xml_inner('member', service)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_application(self, name, application='any'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/application'
		element = self.get_xml_inner('member', application)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_user(self, name, user='any'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/source-user'
		element = self.get_xml_inner('member', user)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_source(self, name, source='any'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/source'
		element = self.get_xml_inner('member', source)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_destination(self, name, destination='any'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/destination'
		element = self.get_xml_inner('member', destination)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_category(self, name, category='any'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]/category'
		element = self.get_xml_inner('member', category)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_action(self, name, action='allow'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]'
		element = self.get_xml_inner('action', action)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_policy_disable(self, name, disable='yes'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules/entry[@name="{name}"]'
		element = self.get_xml_inner('disabled', disable)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_zone_interface(self, name, interface):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/zone/entry[@name="{name}"]/network/layer3'
		element = self.get_xml_inner('member', interface)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_router_interface(self, name, interface):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/virtual-router/entry[@name="default"]/interface'
		element = self.get_xml_inner('member', interface)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_router_redistribute_interface(self, name, interface):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/network/virtual-router/entry[@name="default"]/protocol/redist-profile/entry[@name="{name}"]/filter/interface'
		element = self.get_xml_inner('member', interface)
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_nat_zone_source(self, name, source):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry[@name="{name}"]/to'
		element = self.get_xml_inner('member', source, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_nat_zone_destination(self, name, destination):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry[@name="{name}"]/from'
		element = self.get_xml_inner('member', destination, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_nat_ip_source(self, name, ip):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry[@name="{name}"]/source'
		element = self.get_xml_inner('member', ip, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_nat_ip_destination(self, name, ip):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry[@name="{name}"]/destination'
		element = self.get_xml_inner('member', ip, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_nat_service(self, name, service='any'):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry[@name="{name}"]'
		element = self.get_xml_inner('service', service, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_nat_description(self, name, description):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry[@name="{name}"]'
		element = self.get_xml_inner('description', description, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_nat_translate_destination(self, name, ip):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules/entry[@name="{name}"]/destination-translation'
		element = self.get_xml_inner('translated-address', ip, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_proxy(self, name, number, local, remote):
		xpath = f"/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='{name}']/auto-key/proxy-id"
		proxy_name = 'proxy.' + f'{number}'.zfill(3)
		element = self.create_xml_payload(proxy_name, {'local': local,'remote': remote})
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_ipsec_proxy_from_csv(self, name, filename):
		with open(f'configs/{filename}','r') as f:
			fr = f.read()
		sc = '\r\n' if '\r\n' in fr else '\n'
		fs = fr.split(sc)
		#
		for index,line in enumerate(fs):
			if not line: continue
			local,remote = line.split(',')
			output = self.set_ipsec_proxy(name, index+1, local, remote)
			print(output['result'])
		return
	
	def set_object_ip(self, name, ip):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/address/entry[@name="{name}"]'
		element = self.get_xml_inner('ip-netmask', ip, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def set_object_group_object(self, name, object):
		xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/address-group/entry[@name="{name}"]/static'
		element = self.get_xml_inner('member', object, name='')
		output = self.set_xml_config(xpath, element)
		return output
	
	def _set(self, name):
		xpath = ''
		element = self.get_xml_inner('entry', '', name=name)
		output = self.set_xml_config(xpath, element)
		return output
	
	def get_zone_list(self):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/zone'
		output = self.get_xml_config(xpath)
		return output
	
	def get_policy_list(self):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/security/rules'
		output = self.get_xml_config(xpath)
		return output
	
	def get_tunnel_interface_list(self):
		xpath = '/config/devices/entry[@name="localhost.localdomain"]/network/interface/tunnel/units'
		output = self.get_xml_config(xpath)
		return output
	
	def _get(self):
		xpath = ''
		output = self.get_xml_config(xpath)
		return output
	
	def create_vpn(self, name, peer, key):
		name_up = name.upper()
		name_ike = f'IKE-{name_up}'
		name_crypto = f'CRYPTO-{name_up}'
		name_vpn = f'VPN-{name_up}'
		name_ipsec = f'IPSEC-{name_up}'
		
		print('[I] Creating IPSec')
		self.create_ipsec(name_up)
		
		print('[I] Creating IPSec Crypto')
		self.create_ipsec_crypto(name_crypto)
		
		print('[I] Creating IKE Crypto')
		self.create_ike_crypto(name_crypto)
		
		print('[I] Creating IPSec Proxy')
		self.set_ipsec_proxy_from_csv(name_up, f'{name_up}.txt')
		
		print('[I] Setting IKE Crypto')
		self.set_ike_crypto_group(name_crypto, 'group5')
		self.set_ike_crypto_encryption(name_crypto, 'aes-256-cbc')
		self.set_ike_crypto_hash(name_crypto, 'sha1')
		self.set_ike_crypto_lifetime(name_crypto, '8')
	
		print('[I] Setting IPSec Crypto')
		self.set_ipsec_crypto_group(name_crypto, 'group5')
		self.set_ipsec_crypto_encryption(name_crypto, 'aes-256-cbc')
		self.set_ipsec_crypto_hash(name_crypto, 'sha1')
		self.set_ipsec_crypto_lifetime(name_crypto, '1')
		
		print('[I] Creating IKE Gateway')
		self.create_ike_gateway(name_ike)
		
		print('[I] Setting IKE Gateway')
		self.set_ike_gateway_peer(name_ike, peer)
		self.set_ike_gateway_interface(name_ike)
		self.set_ike_gateway_ip(name_ike)
		self.set_ike_gateway_nat(name_ike)
		self.set_ike_gateway_crypto_profile(name_ike, name_crypto)
		self.set_ike_gateway_psk(name_ike, key)
		
		print('[I] Setting IPSec Crypto Profile')
		self.set_ipsec_crypto_gateway(name_up, name_ike)
		self.set_ipsec_crypto_profile(name_up, name_crypto)
		
		print('[I] Create New Tunnel Interface')
		tunnel_raw = self.get_tunnel_interface_list()
		tunnel_count = tunnel_raw['result'].count('entry name')
		if name_up not in tunnel_raw['result']:
			tunnel_name = f'tunnel.{tunnel_count+1}'
			self.create_tunnel_interface(name_up, f'{tunnel_count + 1}')
		else:
			tunnel_name = f'tunnel.{tunnel_count}'
			print(f'[I] Interface tunnel.{tunnel_count} already created!')
		
		print('[I] Set Tunnel Virtual-Router')
		self.set_router_interface(name_up, tunnel_name)
		
		print('[I] Set Router Redistribute Interface')
		self.set_router_redistribute_interface('S2B', tunnel_name)
		
		print('[I] Set IPSec Tunnel Interface')
		self.set_ipsec_crypto_tunnel(name_up, tunnel_name)
		
		print('[I] Create New Zone')
		zone_raw = self.get_zone_list()
		if name_ipsec not in zone_raw['result']:
			self.create_zone(name_ipsec)
		else:
			print('[I] Zone already created!')
		
		print('[I] Set Zone Interface')
		self.set_zone_interface(name_ipsec, tunnel_name)
		
		print('[I] Create Policy')
		self.create_policy(name_vpn)
		
		print('[I] Set Policy Zone')
		self.set_policy_zone_source(name_vpn, name_ipsec)
		self.set_policy_zone_source(name_vpn, 'trust')
		self.set_policy_zone_destination(name_vpn, name_ipsec)
		self.set_policy_zone_destination(name_vpn, 'trust')
		
		print('[I] Set Policy Defaults')
		self.set_policy_action(name_vpn)
		self.set_policy_application(name_vpn)
		self.set_policy_user(name_vpn)
		self.set_policy_service(name_vpn)
		self.set_policy_category(name_vpn)
		self.set_policy_source(name_vpn)
		self.set_policy_destination(name_vpn)
		
		print('[I] Disable Policy')
		self.set_policy_disable(name_vpn)
		return
	
	def create_nat_translation(self, name, destination, translated):
		self.set_nat_zone_source(name, 'untrust')
		self.set_nat_zone_destination(name, 'trust')
		self.set_nat_ip_source(name, 'any')
		self.set_nat_ip_destination(name, destination)
		self.set_nat_service(name, 'any')
		self.set_nat_description(name, f'{destination} -> {translated}')
		self.set_nat_translate_destination(name, translated)
		return
	
	def _():
		return

if __name__ == '__main__':
	fw = 'palo01.domain.com'
	p = PaloAlto(fw)
	p.login()
	
	# static route
	#xpath = '/config/devices/entry[@name="localhost.localdomain"]/network/virtual-router/entry[@name="default"]/routing-table/ip/static-route/entry[@name="IPSEC-CREDITMANAGEMENT"]'
	# <interface></interface>
	# <destination></destination>
	
	# full tree
	#xpath = '/config/devices/entry[@name="localhost.localdomain"]'
	
	xpath = f'/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/rulebase/nat/rules'
	
	r = p.get_xml('config','get',xpath=xpath)
	#print(r['result'])
	
	print('[I] End')