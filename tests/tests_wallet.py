import unittest
from bitcoin.wallet import Mnemonic, Address

'''
- masterKeyGeneration
	- generateMneumonic
	- Mneumonic to private key
	- Validate private key
	- Derive child key
- convert seed to key
- create p2pkh addresses


test_createMneumonic
1. The mneumonic is in alphabetical order
2. The words are unique within the set
3. There are 12, 15,18,21 or 24 words
4. All the words are contained within the dictionary

'''

class WalletTests(unittest.TestCase):
	
	def setUp(self):
		self.mnemonic = Mnemonic.createMnemonic()
	
	def test_createMneumonic(self):
		mnemonic_length = len(self.mnemonic)
		self.assertIn(mneumonic_length, [12,15,18,21,24])
	
	def test_mneumonic_words_unique(self):
		self.assertEqual(len(self.mnuemonic), len(set(your_list)))
		
	def test_mneumonic_sorted(self):
		self.assertEqual(self.mnemonic, self.mnemonic.sorted())


class AddressTests(unittest.TestCase):
	'''
	self.assertEqual(s.split(), ['hello', 'world'])
	'''
	def setup():
		
	fake_address = '1LFZPZ3RgmmBVnfzmVjwdu1Kp445qE1Mc9'
	qr = QRCode()
	image = qr.create(self.address_str, 'jpg')
	qr.save(image, "qrcode.jpg")
	
	# Get the image from file
	qrd = QRCode()
	decoded_obj = qrd.decode(imagepath)
	self.assertEquals(fake_address, decoded_obj)



class BlockExplorerConnectionTests(unittest.TestCase):
	
	def setUp(self):
		from api.connection import BlockExplorerConnection, BlockExplorers
		self.web_service = BlockExplorerConnection(BlockExplorers.BLOCKEXPLORER)
		
	def test_internet_connection(self):
		pass
	
	def test_timeout(self):
		pass
	
	def bad_address(self):
		fake_address = '1LFZPZ3RgmmBVnfzmVjwdu1Kp445qE1Mc9'
		balance = self.web_service.getAddressBalance(fake_address)
		self.assertIs(balance, TypeError)



if __name__ == '__main__':
	unittest.main()	