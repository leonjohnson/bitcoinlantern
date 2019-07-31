from enum import Enum
from rpc.exceptions import BitcoinException
import requests

class BlockExplorers(Enum):
	BLOCKEXPLORER = 'https://blockexplorer.com/api/addr/'

class BlockExplorerConnection(object):
	def __init__(self, explorer_enum, token=''):
		self.explorer = explorer_enum
		self.token = token
		if token != '':
			headers={'Authorization': 'access_token myToken'}
		
	def getAddressBalance(self, address):
		try:
			response = requests.get(self.explorer.value + address + '/balance', timeout=3)
			if response.text == 'Invalid address: Checksum mismatch. Code:1':
				return TypeError
			return int(response.text)
		except ConnectionError as error:
			print(error)
		# except timeout
		return error