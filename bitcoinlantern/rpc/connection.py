# Copyright (c) 2010 Witchspace <witchspace81@gmail.com>
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
"""
Connect to Bitcoin server via JSON-RPC.
"""
from rpc.proxy import Proxy
from rpc.exceptions import (wrap_exception, BitcoinException)
#								   WalletPassphraseIncorrect,
#								   WalletAlreadyUnlocked)
#from bitcoinrpc.data import (ServerInfo, TransactionInfo, AddressValidation, WorkItem, MiningInfo)


class BitcoinConnection(object):
	"""
	A BitcoinConnection object defines a connection to a bitcoin server.
	It is a thin wrapper around a JSON-RPC API connection.

	Arguments to constructor:

	- *user* -- Authenticate as user.
	- *password* -- Authentication password.
	- *host* -- Bitcoin JSON-RPC host.
	- *port* -- Bitcoin JSON-RPC port.
	"""
	def __init__(self, user, password, host='localhost', port=8332,
				 use_https=False):
		"""
		Create a new bitcoin server connection.
		"""
		url = 'http{s}://{user}:{password}@{host}:{port}/'.format(
			s='s' if use_https else '',
			user=user, password=password, host=host, port=port)
		self.url = url
		print(url)
		self.proxy = Proxy(url)
		

	def stop(self):
		"""
		Stop bitcoin server.
		"""
		self.proxy.stop()

	def getblock(self, hash):
		"""
		Returns information about the given block hash.
		"""
		return self.proxy.getblock(hash)

	def getblockcount(self):
		"""
		Returns the number of blocks in the longest block chain.
		"""
		return self.proxy.call('getblockcount')
		#return self.proxy.getblockcount()

	def getblockhash(self, index):
		"""
		Returns hash of block in best-block-chain at index.

		:param index: index ob the block

		"""
		return self.proxy.getblockhash(index)


	def getconnectioncount(self):
		"""
		Returns the number of connections to other nodes.
		"""
		return self.proxy.getconnectioncount()


'''
	def getdifficulty(self):
		"""
		Returns the proof-of-work difficulty as a multiple of the minimum difficulty.
		"""
		return self.proxy.getdifficulty()

	def getgenerate(self):
		"""
		Returns :const:`True` or :const:`False`, depending on whether generation is enabled.
		"""
		return self.proxy.getgenerate()

	def setgenerate(self, generate, genproclimit=None):
		"""
		Enable or disable generation (mining) of coins.

		Arguments:

		- *generate* -- is :const:`True` or :const:`False` to turn generation on or off.
		- *genproclimit* -- Number of processors that are used for generation, -1 is unlimited.

		"""
		if genproclimit is None:
			return self.proxy.setgenerate(generate)
		else:
			return self.proxy.setgenerate(generate, genproclimit)

	def gethashespersec(self):
		"""
		Returns a recent hashes per second performance measurement while generating.
		"""
		return self.proxy.gethashespersec()

	def getinfo(self):
		"""
		Returns an :class:`~bitcoinrpc.data.ServerInfo` object containing various state info.
		"""
		return ServerInfo(**self.proxy.getinfo())

	def getmininginfo(self):
		"""
		Returns an :class:`~bitcoinrpc.data.MiningInfo` object containing various
		mining state info.
		"""
		return MiningInfo(**self.proxy.getmininginfo())

	
	def getreceivedbyaddress(self, bitcoinaddress, minconf=1):
		"""
		Returns the total amount received by a bitcoin address in transactions with at least a
		certain number of confirmations.

		Arguments:

		- *bitcoinaddress* -- Address to query for total amount.

		- *minconf* -- Number of confirmations to require, defaults to 1.
		"""
		return self.proxy.getreceivedbyaddress(bitcoinaddress, minconf)


	def gettransaction(self, txid):
		"""
		Get detailed information about transaction

		Arguments:

		- *txid* -- Transactiond id for which the info should be returned

		"""
		return TransactionInfo(**self.proxy.gettransaction(txid))

	def getrawtransaction(self, txid, verbose=True):
		"""
		Get transaction raw info

		Arguments:

		- *txid* -- Transactiond id for which the info should be returned.
		- *verbose* -- If False, return only the "hex" of the transaction.

		"""
		if verbose:
			return TransactionInfo(**self.proxy.getrawtransaction(txid, 1))
		return self.proxy.getrawtransaction(txid, 0)

	def gettxout(self, txid, index, mempool=True):
		"""
		Returns details about an unspent transaction output (UTXO)

		Arguments:

		- *txid* -- Transactiond id for which the info should be returned.
		- *index* -- The output index.
		- *mempool* -- Add memory pool transactions.
		"""
		tx = self.proxy.gettxout(txid, index, mempool)
		if tx != None:
			return TransactionInfo(**tx)
		else:
			return TransactionInfo()

	def createrawtransaction(self, inputs, outputs):
		"""
		Creates a raw transaction spending given inputs
		(a list of dictionaries, each containing a transaction id and an output number),
		sending to given address(es).

		Returns hex-encoded raw transaction.

		Example usage:
		>>> conn.createrawtransaction(
				[{"txid": "a9d4599e15b53f3eb531608ddb31f48c695c3d0b3538a6bda871e8b34f2f430c",
				  "vout": 0}],
				{"mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT":50})


		Arguments:

		- *inputs* -- A list of {"txid": txid, "vout": n} dictionaries.
		- *outputs* -- A dictionary mapping (public) addresses to the amount
					   they are to be paid.
		"""
		return self.proxy.createrawtransaction(inputs, outputs)

	def signrawtransaction(self, hexstring, previous_transactions=None, private_keys=None):
		"""
		Sign inputs for raw transaction (serialized, hex-encoded).

		Returns a dictionary with the keys:
			"hex": raw transaction with signature(s) (hex-encoded string)
			"complete": 1 if transaction has a complete set of signature(s), 0 if not

		Arguments:

		- *hexstring* -- A hex string of the transaction to sign.
		- *previous_transactions* -- A (possibly empty) list of dictionaries of the form:
			{"txid": txid, "vout": n, "scriptPubKey": hex, "redeemScript": hex}, representing
			previous transaction outputs that this transaction depends on but may not yet be
			in the block chain.
		- *private_keys* -- A (possibly empty) list of base58-encoded private
			keys that, if given, will be the only keys used to sign the transaction.
		"""
		return dict(self.proxy.signrawtransaction(hexstring, previous_transactions, private_keys))

	def decoderawtransaction(self, hexstring):
		"""
		Produces a human-readable JSON object for a raw transaction.

		Arguments:

		- *hexstring* -- A hex string of the transaction to be decoded.
		"""
		return dict(self.proxy.decoderawtransaction(hexstring))

	def listsinceblock(self, block_hash):
		res = self.proxy.listsinceblock(block_hash)
		res['transactions'] = [TransactionInfo(**x) for x in res['transactions']]
		return res

	
	def validateaddress(self, validateaddress):
		"""
		Validate a bitcoin address and return information for it.

		The information is represented by a :class:`~bitcoinrpc.data.AddressValidation` object.

		Arguments: -- Address to validate.


		- *validateaddress*
		"""
		return AddressValidation(**self.proxy.validateaddress(validateaddress))

	def getbalance(self, account=None, minconf=None):
		"""
		Get the current balance, either for an account or the total server balance.

		Arguments:
		- *account* -- If this parameter is specified, returns the balance in the account.
		- *minconf* -- Minimum number of confirmations required for transferred balance.

		"""
		args = []
		if account is not None:
			args.append(account)
			if minconf is not None:
				args.append(minconf)
		return self.proxy.getbalance(*args)

	def verifymessage(self, bitcoinaddress, signature, message):
		"""
		Verifies a signature given the bitcoinaddress used to sign,
		the signature itself, and the message that was signed.
		Returns :const:`True` if the signature is valid, and :const:`False` if it is invalid.

		Arguments:

		- *bitcoinaddress* -- the bitcoinaddress used to sign the message
		- *signature* -- the signature to be verified
		- *message* -- the message that was originally signed

		"""
		return self.proxy.verifymessage(bitcoinaddress, signature, message)

	def getwork(self, data=None):
		"""
		Get work for remote mining, or submit result.
		If data is specified, the server tries to solve the block
		using the provided data and returns :const:`True` if it was successful.
		If not, the function returns formatted hash data (:class:`~bitcoinrpc.data.WorkItem`)
		to work on.

		Arguments:

		- *data* -- Result from remote mining.

		"""
		if data is None:
			# Only if no data provided, it returns a WorkItem
			return WorkItem(**self.proxy.getwork())
		else:
			return self.proxy.getwork(data)

	def verifymessage(self, address, signature, message):
		"""
		Verify a signed message

		:param address: Bitcoin address used to sign a message
		:type address: str or unicode
		:param signature: The signature
		:type signature: unicode
		:param message: The message to sign
		:type message: str or unicode
		:rtype: bool
		"""
		return self.proxy.verifymessage(address, signature, message)




'''