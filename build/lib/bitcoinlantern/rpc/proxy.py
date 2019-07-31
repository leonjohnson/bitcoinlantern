import http.client as httplib
import base64
import json
import decimal
import requests
import urllib.parse as urlparse
from collections import defaultdict, deque
from .exceptions import TransportException

USER_AGENT = "AuthServiceProxy/0.1"
HTTP_TIMEOUT = 30

class HTTPTransport(object):
	def __init__(self, service_url):
		self.service_url = service_url
		self.parsed_url = urlparse.urlparse(service_url)
		if self.parsed_url.port is None:
			port = 80
		else:
			port = self.parsed_url.port
		print('Port is: ')
		print(port)
		authpair = "%s:%s" % (self.parsed_url.username,
							  self.parsed_url.password)
		authpair = authpair.encode('utf8')
		self.auth_header = "Basic ".encode('utf8') + base64.b64encode(authpair)
		if self.parsed_url.scheme == 'https':
			self.connection = httplib.HTTPSConnection(self.parsed_url.hostname,
													  port, None, None, False,
													  HTTP_TIMEOUT)
		else:
			self.connection = httplib.HTTPConnection(self.parsed_url.hostname,
													 port, False, HTTP_TIMEOUT)

	def request(self, serialized_data):
		self.connection.request('POST', self.parsed_url.path, serialized_data,
								{'Host': self.parsed_url.hostname,
								 'User-Agent': USER_AGENT,
								 'Authorization': self.auth_header,
								 'Content-type': 'application/json'})

		httpresp = self.connection.getresponse()
		if httpresp is None:
			self._raise_exception({
				'code': -342, 'message': 'missing HTTP response from server'})
		elif httpresp.status == httplib.FORBIDDEN:
			msg = "bitcoind returns 403 Forbidden. Is your IP allowed?"
			raise TransportException(msg, code=403,
									 protocol=self.parsed_url.scheme,
									 raw_detail=httpresp)

		resp = httpresp.read()
		return resp.decode('utf8')



class Proxy():
	"""
	You can use custom transport to test your app's behavior without calling
	the remote service.
	exception_wrapper is a callable accepting a dictionary containing error
	code and message and returning a suitable exception object.
	"""
	def __init__(self, url):
		''' 
		self._service_url = service_url
		self._id_counter = 0
		self._exception_wrapper = exception_wrapper
		'''
		
		self._session = requests.Session()
		self._url = url
		self._headers = {'content-type': 'application/json'}
	
	def call(self, rpcMethod, *params):
		payload = json.dumps({"method": rpcMethod, "params": list(params), "jsonrpc": "2.0"})
		tries = 5
		hadConnectionFailures = False
		while True:
			try:
				response = self._session.post(self._url, headers=self._headers, data=payload)
			except requests.exceptions.ConnectionError:
				tries -= 1
				if tries == 0:
					raise Exception('Failed to connect for remote procedure call.')
				hadFailedConnections = True
				print("Couldn't connect for remote procedure call, will sleep for five seconds and then try again ({} more tries)".format(tries))
				time.sleep(10)
			else:
				if hadConnectionFailures:
					print('Connected for remote procedure call after retry.')
				break
		if not response.status_code in (200, 500):
			raise Exception('RPC connection failure: ' + str(response.status_code) + ' ' + response.reason)
		responseJSON = response.json()
		if 'error' in responseJSON and responseJSON['error'] != None:
			raise Exception('Error in RPC call: ' + str(responseJSON['error']))
		return responseJSON['result']
		
	def __getattr__(self, name):
		return RPCMethod(name, self)
	
	def _get_method(self, name):
		"""
		Get method instance when the name contains forbidden characters or
		already taken by internal attribute.
		"""
		return RPCMethod(name, self)
	
	def _raise_exception(self, error):
		if self._exception_wrapper is None:
			raise JSONRPCException(error)
		else:
			raise self._exception_wrapper(error)
			

class RPCMethod(object):
	def __init__(self, name, service_proxy):
		self._method_name = name
		self._service_proxy = service_proxy

	def __getattr__(self, name):
		new_name = '{}.{}'.format(self._method_name, name)
		return RPCMethod(new_name, self._service_proxy)

	def __call__(self, *args):
		self._service_proxy._id_counter += 1
		data = {'version': '1.1',
				'method': self._method_name,
				'params': args,
				'id': self._service_proxy._id_counter}
		postdata = json.dumps(data)
		resp = self._service_proxy._transport.request(postdata)
		resp = json.loads(resp, parse_float=decimal.Decimal)

		if resp['error'] is not None:
			self._service_proxy._raise_exception(resp['error'])
		elif 'result' not in resp:
			self._service_proxy._raise_exception({
				'code': -343, 'message': 'missing JSON-RPC result'})
		else:
			return resp['result']

	def __repr__(self):
		return '<RPCMethod object "{name}">'.format(name=self._method_name)