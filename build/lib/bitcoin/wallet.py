import os.path
import sys
import binascii
import hashlib
import hmac
import unicodedata
import base58

from .ecc import Point, S256Field, A, B, N
from .helper import encode_base58, encode_base58_checksum, decode_base58, hash160, hash256, int_to_little_endian, little_endian_to_int


from enum import Enum

from .op import op_equal, op_hash160, op_verify, OP_CODE_FUNCTIONS, OP_CODE_FUNCTIONS, OP_CODE_NAMES

PBKDF2_ROUNDS = 2048

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"



class WalletType(Enum):
	P2PKH = 1
	P2SH = 2
	Bech32 = 3
	
	

class Address(object):
	'''
	A class that encapsulates a Bitcoin address.
	
	Usage:
		Use this class to get information related to a Bitcoin address
	
	Args:
		compressed: Bool
		testnet: Bool
		type: Bech32, P2PKH, etc
		seed: a hexidecimal represnetation of the seed
		mnemonic: a series of words that can be used to generate the seed
	
	Raises:
		To be added.
	
	Returns:
		An address object.
	
	'''
	def __init__(self, compressed, testnet, address_str, address_type, seed, mnemonic):
		self.compressed=True
		self.testnet=False
		self.type = address_type
		self.address_str= address_str
		self.seed = seed
		self.mnemonic = mnemonic

	def private_key(self):
		'''In Electrum, import bc1 addresses by prepending the pk with p2wpkh:'''
		seed_int = int.from_bytes(self.seed, 'big')
		priv_key = PrivateKey(seed_int)
		return priv_key.wif(compressed=True, testnet=False)

	def add_type(self):
		net_type = 'Testnet' if self.testnet == True else 'Mainnet'
		return 'This is a ' + self.type + ' address on ' + net_type + '.'
	
	def qr_code(self):
		qr = QRCode()
		image = qr.create(self.address_str, 'jpg')
		qr.save(image, "qrcode.jpg")
		return 
	
	def get_balance(self):
		if self.type == 'xpub':
			return 'TODO: Fetching the balance of xpub addresses.'
		from api.connection import BlockExplorerConnection, BlockExplorers
		web_service = BlockExplorerConnection(BlockExplorers.BLOCKEXPLORER)
		print('Fetching the balance...')
		return web_service.getAddressBalance(self.address_str)
	
	def string(self):
		return self.address_str
		
	def __str__(self):
		return self.address_str # So it prints nicely		
	

class Mnemonic(object):
	'''	
	This class creates mnemonics and seeds.
	
	Usage:
		Use this class to create a mnemonic.
		
	Args:
		entrophy - optional
	
	Raises:
		Coming soon
	
	Returns:
		An object representing a mnemonic
	
	'''
	
	def __init__(self, language='english'):
		self.wordlist_count = 2048
		self.wordlist = ''
		with open("%s/%s.txt" % (self._get_directory(), language), "r", encoding="utf-8") as f:
			self.wordlist = [w.strip() for w in f.readlines()]
		# We now have our wordlist in 'wordlist'
		if len(self.wordlist) != self.wordlist_count:
			raise ConfigurationError("The wordlist should have %d words in it but it has %d words" % (self.wordlist_count, len(self.wordlist)))
	
	def create_mnemonic(self, entrophy):
		entrophy_length = len(entrophy)
		if entrophy_length not in [16, 20, 24, 28, 32]:
			raise ValueError("Data length should be one of the following: [16, 20, 24, 28, 32], but it is (%d)." % entrophy_length)
		
		#SHA256 the entrophy and spit it out
		h = hashlib.sha256(entrophy).hexdigest()
		
		# Bin returns the binary equivalent string of a given integer
		checksum = bin(int(h, 16))[2:].zfill(256)[: entrophy_length * 8 // 32]
		
		# The binascii hexadecimal representation of the binary data
		b = (bin(int(binascii.hexlify(entrophy), 16))[2:].zfill(entrophy_length * 8) + checksum)
		
		# Next, these concatenated bits (b) are split into groups of 11 bits, each encoding a number from 0-2047, serving as an index into a wordlist.
		result = []
		for i in range(len(b) // 11):
			idx = int(b[i * 11 : (i + 1) * 11], 2)
			# Finally, we convert these numbers into words
			result.append(self.wordlist[idx])
			# and use the joined words as a mnemonic sentence.
			result_phrase = " ".join(result)
		return result_phrase
	
	@classmethod
	def normalize_string(cls, txt):
		if isinstance(txt, str if sys.version < "3" else bytes):
			utxt = txt.decode("utf8")
		elif isinstance(txt, unicode if sys.version < "3" else str):
			utxt = txt
		else:
			raise TypeError("String value expected")
		return unicodedata.normalize("NFKD", utxt)
		
	@classmethod
	def to_seed(cls, mnemonic, include_chaincode, passphrase=""):
		mnemonic = cls.normalize_string(mnemonic)
		passphrase = cls.normalize_string(passphrase)
		passphrase = "mnemonic" + passphrase
		mnemonic = mnemonic.encode("utf-8")
		passphrase = passphrase.encode("utf-8")
		# dklen is the length of the derived key. If dklen is None then the digest size of the hash algorithm hash_name is used, e.g. 64 for SHA-512.
		dklen = 32
		if include_chaincode == True:
			dklen = 64	
		stretched = hashlib.pbkdf2_hmac("sha512", mnemonic, passphrase, PBKDF2_ROUNDS, dklen=dklen)
		return stretched
				
	def _get_directory(cls):
		return os.path.join(os.path.dirname(__file__), 'words')
	

class Wallet(object):
	'''
	A class that represents a wallet.
	
	Usage
	-----
		This will probably be one of the first objects you create. 
		Create a wallet to hold all of the Address objects you create (each have a public/private key pair).
	
	Args
	----
		None
	
	
	Raises
	------
		TBD
	
	
	Returns
	-------
		An Address() object
	
	'''
	
	def __init__(self):
		self.addresses = []
		self.network = 'Mainnet'
	
	def get_network(self):
		return self.network
	
	def is_testnet(self):
		if self.network.capitalize() == 'Testnet': 
			return True 
		else:
			return False
			
	def entrophy(self, strength=256):
		if strength not in [128, 256]:# We refer to the initial entropy length as ENT. The allowed size of ENT is 128-256 bits.
			raise ValueError('Stength has to be 128 or 256 bits')
		r = os.urandom(strength // 8)# this returns bytes
		return r
	
	def createPrivateKey(self, compressed=True, entro=None, include_chaincode=False, passphrase=""):
		if entro == None:
				entrophy = self.entrophy()
		else:
			entrophy = entro
		# seed = int.from_bytes(entrophy, 'big')
		mnemonic = Mnemonic().create_mnemonic(entrophy)
		binary_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase, include_chaincode=include_chaincode)
		binary_seed_int = int.from_bytes(binary_seed, 'big')
		priv_key = PrivateKey(binary_seed_int)
		return (priv_key, mnemonic, binary_seed)
	
	def createP2SH(self, compressed=True, entro=None):
		'''
		Compressed public key (hex string) -> p2wpkh nested in p2sh address. 'SegWit address.'
		'''
		
		priv_key, mnemonic, binary_seed  = self.createPrivateKey()
		h160 = self.hash160(compressed=True)
		push_20 = bytes.fromhex("0014")
		# Script sig is just PUSH(20){hash160(cpk)}
		script_sig = push_20 + h160
		
		# Address is then prefix + hash160(script_sig)
		if self.is_testnet():
			prefix = b"\xc4"
		else:
			prefix = b"\x05"
		address_string = encode_base58_checksum(prefix + hash160(script_sig))	
		address = Address( address_str=address_string, mnemonic=mnemonic, seed=binary_seed, address_type=WalletType.P2SH.value)
		return address
				
	def createP2PKH(self, compressed=True, entro=None):
		priv_key, mnemonic, binary_seed = self.createPrivateKey()
		#1. Take the SEC format (compressed or uncompressed) - self
		
		#2. Do a hash160 - SHA256 followed by the ripemd160
		h160 = self.hash160(compressed)
		if self.is_testnet():
			prefix = b'\x6f'
		else:
			prefix = b'\x00'
		
		#3. Add the prefix to the hash160 and encode it in base58
		address_string = encode_base58_checksum(prefix + h160)
		
		address = Address(compressed=compressed, testnet=testnet, address_str=address_string, mnemonic=mnemonic, seed=binary_seed, address_type=WalletType.P2PKH.value)
		self.addresses.append(address)
		return address
	
	def create_master_xpub(self, compressed=True, entro=None):
		priv_key, mnemonic, original_seed = self.createPrivateKey(include_chaincode=True)
		if len(original_seed) != 64:
			raise ValueError("Provided seed should have length of 64")
		# Compute HMAC-SHA512 of seed
		seed = hmac.new(b"Bitcoin seed", original_seed, digestmod=hashlib.sha512).digest()
				
		int_seed = int.from_bytes(seed[:32], 'big')
		test_hex = int_seed.to_bytes(64, 'big')		
		prkey = PrivateKey(int_seed)

		# Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
		xprv = b"\x04\x88\xad\xe4"  # Version for private mainnet
		xprv += b"\x00" * 9  # Depth, parent fingerprint, and child number
		xprv += seed[32:]  # Chain code
		xprv += b"\x00" + seed[:32]  # Master key
		xprv = encode_base58_checksum(xprv) # Return base58 for xpriv
		
		sec = prkey.point.sec()
		xpub = b"\x04\x88\xb2\x1e"  # Version for public mainnet
		xpub += b"\x00" * 9  # Depth, parent fingerprint, and child number
		xpub += seed[32:]  # Chain code
		xpub += sec  # Master key
		xpub = encode_base58_checksum(xpub) # Return base58 for xpub
		
		#Create addresses
		address = Address(compressed=compressed, testnet=self.is_testnet(), address_str=xpub, mnemonic=mnemonic, seed=seed, address_type=WalletType.Bech32.value)
		self.addresses.append(address)
		return (xprv, xpub, prkey.point)
	
	def create_child_xpub(self, xpub, index, parent_pubkey_point):

		assert xpub is not None
		index_as_bytes = (index).to_bytes(4, 'big')
		
		version, depth, parent_fingerprint, child, chain_code, pub_key = self.deserialise_xpub(xpub)
		
		I = hmac.new(chain_code, msg=(pub_key + index_as_bytes), digestmod=hashlib.sha512).digest()
		I_L, I_R = I[:32], I[32:]
		
		left_num = int.from_bytes(I_L,'big')
		child_pubkey_point = PrivateKey(left_num).point + parent_pubkey_point
		child_pubkey = child_pubkey_point.sec()
		
		fingerprint = hash160(pub_key)
		
		xpub = b"\x04\x88\xb2\x1e"  # Version for public mainnet
		xpub += b"\x01" # Depth - says we're dealing with the second slot (index 1)
		xpub += fingerprint[:4] # parent fingerprint
		xpub += index_as_bytes # child number m/0/0 - the number in the second slot.
		xpub += I_R  # Chain code
		xpub += child_pubkey  # Master key
		
		# Return base58 for xpub
		xpub = encode_base58_checksum(xpub)
		return xpub, child_pubkey_point
	
	# Utility function, not used directly.
	def deserialise_xpub(self, xpub):
		decoded_xpub = base58.b58decode_check(xpub)
		version, depth, parent_fingerprint, child, chain_code, pub_key = (
		decoded_xpub[:4], decoded_xpub[4], decoded_xpub[5:9], decoded_xpub[9:13], decoded_xpub[13:45], decoded_xpub[45:])
		return(version, depth, parent_fingerprint, child, chain_code, pub_key)
	
	def derivationPath(self, path, xpub, parent_pubkey_point):
		assert path is not None
		point = parent_pubkey_point
		#path = path + 1 # added one to make it loopable to the correct point of termination.
		version, depth, parent_fingerprint, child, chaincode, pubkey = self.deserialise_xpub(xpub)
		pubkey, chaincode, point = self.ckd(pubkey, chaincode, point, path)
		return self.xpub_to_address(pubkey)
				
	
	def ckd(self, parent_pubkey, parent_chaincode, parent_pubkey_point, index):
		assert parent_pubkey is not None
		assert parent_chaincode is not None 
		assert parent_pubkey_point is not None 
		assert index is not None
		if index >= 2** 31:
			return
		
		# I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
		# Split I into two 32-byte sequences, IL and IR.
		# The returned child key Ki is point(parse256(IL)) + Kpar.
		# The returned chain code ci is IR.
		index_as_bytes = (index).to_bytes(4, 'big')
		# version, depth, parent_fingerprint, child, parent_chaincode, parent_pubkey = self.deserialise_xpub(xpub)
		I = hmac.new(parent_chaincode, msg=(parent_pubkey+index_as_bytes), digestmod=hashlib.sha512).digest()
		I_L, I_R = I[:32], I[32:]		
		
		left_num = int.from_bytes(I_L,'big')
		child_pubkey = PrivateKey(left_num).point + parent_pubkey_point
		# test if at point of infinity 
		child_pubkey = child_pubkey.sec()
		child_pubkey_int = int.from_bytes(child_pubkey, 'big')
		child_chaincode = I[32:]
		point = PrivateKey(child_pubkey_int).point
		return (child_pubkey, child_chaincode, point)
		# return (self.xpub_to_address(child_pubkey, index))

	# Now call the above twice
		
	def xpub_to_address(self, child_pubkey) ->str:
			# 1. Do a hash160
			hashed_pub_key = hash160(child_pubkey)
			if self.is_testnet():
				prefix = b'\x6f'
			else:
				prefix = b'\x00'
			
			#3. Add the prefix to the hash160 and encode it in base58
			address_string = encode_base58_checksum(prefix + hashed_pub_key)
			return address_string
		
	def create_address_at_path(self, master_xpub, path, point) -> str:
		assert path is not None
		path_elements = path.split(',').strip()
		ext_xpub, cpk_point = w.create_child_xpub(master_xpub, int(path_elements[0]), point)
		address = self.derivationPath(int(path_elements[1]), ext_xpub, cpk_point)
		return address
	
	''' 
	TODO - Write a function that converts SEC public key into a S256Point
	''' 	
	def create_addresses_from_path(self, master_xpub, path):
		assert path is not None
		path_elements = path.split(',')
		starting_element = int(path_elements[1])
		assert len(path_elements) == 2
		
		# Get point
		_, _, _, _, _, pub_key = self.deserialise_xpub(master_xpub)
		derived_point = S256Point.parse(pub_key)
		
		'''
		
		print('Who luuuuves orange soda?')
		print('Kel luuuuuves orange soda!')
		print('Is it true?')
		print(derived_point == point)
		'''
		
		ext_xpub, cpk_point = self.create_child_xpub(master_xpub, int(path_elements[0]), derived_point)
		for i in range(starting_element, 2**31):
			address = self.derivationPath(i, ext_xpub, cpk_point)
			yield address
	
	# next is to call next on the function above.
			
	def mnemonic_to_address(self, mnemonic:str, address_type):
		'''
		TODO: 
		1. Find out whether creating a xpub, p2pkh, and bech32 from the same seed causes issues.
		'''
		
		testnet = self.is_testnet()
		binary_seed = Mnemonic.to_seed(mnemonic, passphrase="")
		binary_seed = int.from_bytes(binary_seed, 'big')
		priv_key = PrivateKey(binary_seed)
		
		if address_type == WalletType.P2PKH.value:
			address_string = priv_key.point.P2PKH(compressed=compressed, testnet=testnet)
		elif address_type == WalletType.P2SH.value:
			address_string = priv_key.point.P2SH(compressed=compressed, testnet=testnet)
		elif address_type == WalletType.Bech32.value:
			address_string = priv_key.point.Bech32(compressed=compressed, testnet=testnet)
		else:
			print('Acceptable values are: P2PKH, P2SH, and Bech32. %s is not a valid entry', address_type)
			raise ValueError
		address = Address(compressed=compressed, testnet=testnet, address_str=address_string, mnemonic=mnemonic, seed=binary_seed, address_type=address_type)
		self.addresses.append(address)
		return address
	
	
	def createBech32(self, testnet=False, entro=None):
		"""Reference implementation for Bech32 and segwit addresses."""
		
		priv_key, mnemonic, binary_seed = self.createPrivateKey()
		
		script_sig = priv_key.point.hash160(compressed=True)
		# Script sig is just PUSH(20){hash160(cpk)}
		#push_20 = bytes.fromhex("0020")
		
		compressed_pub_key = script_sig
				
		# hash160_pub_key = hash160(compressed_pub_key)
		# hash160_pub_key = hash160('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
				
		bc_address = self.encode('bc', 0, compressed_pub_key)		
		address = Address(compressed=True, testnet=self.is_testnet(), address_str=bc_address, mnemonic=mnemonic, seed=binary_seed, address_type='Bech32')
		self.addresses.append(address)
		return address
	
	# Copyright (c) 2017 Pieter Wuille
	#
	# Permission is hereby granted, free of charge, to any person obtaining a copy
	# of this software and associated documentation files (the "Software"), to deal
	# in the Software without restriction, including without limitation the rights
	# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	# copies of the Software, and to permit persons to whom the Software is
	# furnished to do so, subject to the following conditions:
	#
	# The above copyright notice and this permission notice shall be included in
	# all copies or substantial portions of the Software.
	#
	# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	# THE SOFTWARE.
	
	
	def bech32_polymod(self, values):
		"""Internal function that computes the Bech32 checksum."""
		generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
		chk = 1
		for value in values:
			top = chk >> 25
			chk = (chk & 0x1ffffff) << 5 ^ value
			for i in range(5):
				chk ^= generator[i] if ((top >> i) & 1) else 0
		return chk
	
	
	def bech32_hrp_expand(self, hrp):
		"""Expand the HRP into values for checksum computation."""
		return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
	
	
	def bech32_verify_checksum(self, hrp, data):
		"""Verify a checksum given HRP and converted data characters."""
		return self.bech32_polymod(self.bech32_hrp_expand(hrp) + data) == 1
	
	
	def bech32_create_checksum(self, hrp, data):
		"""Compute the checksum values given HRP and data."""
		values = self.bech32_hrp_expand(hrp) + data
		polymod = self.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
		return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
	
	
	def bech32_encode(self, hrp, data):
		"""Compute a Bech32 string given HRP and data values."""
		combined = data + self.bech32_create_checksum(hrp, data)
		return hrp + '1' + ''.join([CHARSET[d] for d in combined])
	
	
	def bech32_decode(self, bech):
		"""Validate a Bech32 string, and determine HRP and data."""
		if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
				(bech.lower() != bech and bech.upper() != bech)):
			return (None, None)
		bech = bech.lower()
		pos = bech.rfind('1')
		if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
			return (None, None)
		if not all(x in CHARSET for x in bech[pos+1:]):
			return (None, None)
		hrp = bech[:pos]
		data = [CHARSET.find(x) for x in bech[pos+1:]]
		if not self.bech32_verify_checksum(hrp, data):
			return (None, None)
		return (hrp, data[:-6])
	
	
	def convertbits(self, data, frombits, tobits, pad=True):
		"""General power-of-2 base conversion."""
		acc = 0
		bits = 0
		ret = []
		maxv = (1 << tobits) - 1
		max_acc = (1 << (frombits + tobits - 1)) - 1
		for value in data:
			if value < 0 or (value >> frombits):
				return None
			acc = ((acc << frombits) | value) & max_acc
			bits += frombits
			while bits >= tobits:
				bits -= tobits
				ret.append((acc >> bits) & maxv)
		if pad:
			if bits:
				ret.append((acc << (tobits - bits)) & maxv)
		elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
			return None
		return ret
	
	
	def decode(self, hrp, addr):
		"""Decode a segwit address."""
		hrpgot, data = self.bech32_decode(addr)
		if hrpgot != hrp:
			return (None, None)
		decoded = self.convertbits(data[1:], 5, 8, False)
		if decoded is None or len(decoded) < 2 or len(decoded) > 40:
			return (None, None)
		if data[0] > 16:
			return (None, None)
		if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
			return (None, None)
		return (data[0], decoded)
	
	
	def encode(self, hrp, witver, witprog):
		"""Encode a segwit address."""
		ret = self.bech32_encode(hrp, [witver] + self.convertbits(witprog, 8, 5)	)
		if self.decode(hrp, ret) == (None, None):
			return None
		return ret

class QRCode:	
	'''
	Description
	------------
		A class that represents a QR code. Use the create function to create a QR code.
	
	
	Usage
	-----
		w = Wallet()
		bitcoin_address = w.createBech32()
		q = QRCode
		qr_code = q.create(bitcoin_address,'svg')
	
	Args
	----
		None
	
	
	Raises
	------
		TBD
	
	
	Returns
	-------
		An QR code image.
	
	'''
	def create(self, data: str, qrcode_format: str):
		'''Add error checking for parameters'''		
		import pyqrcode
		qr_code = pyqrcode.create(data)
		
		if qrcode_format == 'svg':
			qr_code.svg('address.svg', scale=8)
		elif qrcode_format == 'jpg':
			qr_code.jpg('address.jpg', scale=8)
		else:
			qr_code.png('address.png', scale=8)
		return qr_code
	
	def save(self, img, path):
		with open('qr.png', 'w') as fstream:
			qr_code.png(fstream, scale=5)
		return
	
	def decode(self, imagepath):
		import qrtools
		qr = qrtools.QR()
		qr.decode(imagepath)
		print (qr.data)

		
class Xpub:
	def __init__(self, secret):
		self.secret = secret
		try:
			self.point = secret * G
		except TypeError as e:
			print('You need to supply a number as the secret.')
			
			
class PrivateKey:
	'''	
	Description:
		1. We take the secret e (private key)  
		2. multiply it by G, which gives us a point. 
		3. We then turn that into sec format, 
		4. then hash160 it, 
		5. then prefix it for mainnet and 
		6. encode it as base_58
	
	Usage:
		You probably won't need to use this class directly although you could.
		
	Args:
		secret (int): The randomly generated number that must be kept secret.
	
	Raises:
		TypeError: if secret is not a number.
	
	Returns:
		An object representing a Private Key.
	
	'''
	

	
	def __init__(self, secret):
		self.secret = secret
		try:
			self.point = secret * G
		except TypeError as e:
			Print('You need to supply a number as the secret.')
		

	def hex(self):
		return '{:x}'.format(self.secret).zfill(64)

	def sign(self, z):
		k = self.deterministic_k(z)
		# r is the x coordinate of the resulting point k*G
		r = (k * G).x.num
		# remember 1/k = pow(k, N-2, N)
		k_inv = pow(k, N - 2, N)
		# s = (z+r*secret) / k
		s = (z + r * self.secret) * k_inv % N
		if s > N / 2:
			s = N - s
		# return an instance of Signature:
		# Signature(r, s)
		return Signature(r, s)

	def deterministic_k(self, z):
		k = b'\x00' * 32
		v = b'\x01' * 32
		if z > N:
			z -= N
		z_bytes = z.to_bytes(32, 'big')
		secret_bytes = self.secret.to_bytes(32, 'big')
		s256 = hashlib.sha256
		k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
		v = hmac.new(k, v, s256).digest()
		k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
		v = hmac.new(k, v, s256).digest()
		while True:
			v = hmac.new(k, v, s256).digest()
			candidate = int.from_bytes(v, 'big')
			if candidate >= 1 and candidate < N:
				return candidate
			k = hmac.new(k, v + b'\x00', s256).digest()
			v = hmac.new(k, v, s256).digest()

	# Wallet Import Format
	def wif(self, compressed=True, testnet=False):

		#encode the secret in 32 bytes
		try:
			secret_bytes = self.secret.to_bytes(32, 'big')
		except:
			secret_bytes = self.secret.to_bytes(64, 'big')
		if testnet:
			prefix = b'\xef'
		else:
			prefix = b'\x80'
		if compressed:
			suffix = b'\x01'
		else:
			suffix = b''
		#add the prefix, bytes, and suffix
		return encode_base58_checksum(prefix + secret_bytes + suffix)


class S256Point(Point):
	'''	
	This is the public key creation class, it converts a point on the elliptic curve into sec format.
	
	Usage
	-----
		You probably won't need to use this class directly.
		
	Args
	----
		The Point which is created from Privatekey().
	
	Raises
	------
		An error is the point is at the point of infinity.
	
	Returns
	-------
		A public key(sec formatted).
	
	'''
	
	def __init__(self, x, y, a=None, b=None):
		a, b = S256Field(A), S256Field(B)
		if type(x) == int:
			super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
		else:
			super().__init__(x=x, y=y, a=a, b=b)

	def __repr__(self):
		if self.x is None:
			return 'S256Point(infinity)'
		else:
			return 'S256Point({}, {})'.format(self.x, self.y)

	def __rmul__(self, coefficient):
		coef = coefficient % N
		return super().__rmul__(coef)

	def verify(self, z, sig):
		# By Fermat's Little Theorem, 1/s = pow(s, N-2, N)
		s_inv = pow(sig.s, N - 2, N)
		# u = z / s
		u = z * s_inv % N
		# v = r / s
		v = sig.r * s_inv % N
		# u*G + v*P should have as the x coordinate, r
		total = u * G + v * self
		return total.x.num == sig.r

	def sec(self, compressed=True):
		'''returns the binary version of the SEC format'''
		# The big advantage of the compressed SEC format is that it only takes up 33 bytes instead of 65 bytes.
		if compressed:
			if self.y.num % 2 == 0:
				return b'\x02' + self.x.num.to_bytes(32, 'big')
			else:
				return b'\x03' + self.x.num.to_bytes(32, 'big')
		else:
			return b'\x04' + self.x.num.to_bytes(32, 'big') + \
				self.y.num.to_bytes(32, 'big')
	@classmethod
	def parse(self, sec_bin):
		'''returns a Point object from a SEC binary (not hex)''' 
		if sec_bin[0] == 4:
			x = int.from_bytes(sec_bin[1:33], 'big') 
			y = int.from_bytes(sec_bin[33:65], 'big') 
			return S256Point(x=x, y=y)
		is_even = sec_bin[0] == 2
		x = S256Field(int.from_bytes(sec_bin[1:], 'big')) 
		# right side of the equation y^2 = x^3 + 7
		alpha = x**3 + S256Field(B)
		# solve for left side
		beta = alpha.sqrt()
		if beta.num % 2 == 0:
			even_beta = beta
			odd_beta = S256Field(P - beta.num) 
		else:
			even_beta = S256Field(P - beta.num)
			odd_beta = beta 
		if is_even:
			return S256Point(x, even_beta) 
		else:
			return S256Point(x, odd_beta)
	
	def hash160(self, compressed=True):
		return hash160(self.sec(compressed))
	
	def hash256(self, compressed=True):
		return hash256(self.sec(compressed))


'''
	def address(self, compressed=True, testnet=False):
		# Returns the address string

		#1. Take the SEC format (compressed or uncompressed) - self

		#2. Do a hash160 - SHA256 followed by the ripemd160
		h160 = self.hash160(compressed)
		if testnet:
			prefix = b'\x6f'
		else:
			prefix = b'\x00'
		
		#3. Add the prefix to the hash160 and encode it in base58
		address = encode_base58_checksum(prefix + h160)
		return address



	def p2sh(self, testnet=False):
		"""
		Compressed public key (hex string) -> p2wpkh nested in p2sh address. 'SegWit address.'
		"""
		h160 = self.hash160(compressed=True)
		
		# Script sig is just PUSH(20){hash160(cpk)}
		push_20 = bytes.fromhex("0014")
		script_sig = push_20 + h160
	
		# Address is then prefix + hash160(script_sig)
		prefix = b"\xc4" if testnet else b"\x05"
		address = encode_base58_checksum(prefix + hash160(script_sig))
		return address
	
	def bech(self, testnet=False):
		"""
		Compressed public key (hex string) -> p2wpkh nested in p2sh address. 'SegWit address.'
		"""
		h160 = self.hash160(compressed=True)
		
		# Script sig is just PUSH(20){hash160(cpk)}
		push_20 = bytes.fromhex("0020")
		script_sig = h160
		return script_sig

				
	@classmethod
	def parse(self, sec_bin):
		#returns a Point object from a SEC binary (not hex)
		if sec_bin[0] == 4:  # <1>
			x = int.from_bytes(sec_bin[1:33], 'big')
			y = int.from_bytes(sec_bin[33:65], 'big')
			return S256Point(x=x, y=y)
		is_even = sec_bin[0] == 2  # <2>
		x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
		# right side of the equation y^2 = x^3 + 7
		alpha = x**3 + S256Field(B)
		# solve for left side
		beta = alpha.sqrt()  # <3>
		if beta.num % 2 == 0:  # <4>
			even_beta = beta
			odd_beta = S256Field(P - beta.num)
		else:
			even_beta = S256Field(P - beta.num)
			odd_beta = beta
		if is_even:
			return S256Point(x, even_beta)
		else:
			return S256Point(x, odd_beta)


'''
G = S256Point(
	0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
	0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141		