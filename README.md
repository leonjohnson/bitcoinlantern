
# BitcoinLantern

A small Bitcoin library that's delightfully easy to read and easy to use.

Key Features:
- Create a wallet to manage your keys
- Generate keys and addresses (P2PKH, P2SH, Bech32, xpub)
- Generate mnemonics
- Great documentation

Todo:
- RPC: query a full Bitcoin node
- Create and sign a Bitcoin transaction
- Create a Lightning invoice
- Decode a Lightning invoice
- Open a LN channel
- Create and sign a Lightning transaction

With Bitcoin Lantern you can do things such as

```
from bitcoinlantern.bitcoin.wallet import Wallet, Mnemonic, Address

w = Wallet()


address = w.createBech32() # by default the public key is compressed and the address is for mainnet


address.string()
'bc1qh5j2qju2g2rpcvea4yjmdzvgqlmhjdg4sw9k9a'


address.private_key()
'Kwz5z5cqLkr46PZeJQuZhTeNbRQ7LMpBmkQ9dgKfBNedJh14ZLMv'


address.mnemonic	
'mad gun cart mix random nasty suffer snake change beyond liberty maid monster tip ritual alone among hurdle fresh trap curious fan monster decrease'


address.type
'Bech32'
```

### Prerequisites

This python library will run on all platforms that have the following:<br/>
Python 3
Pip

## Getting Started

```
pip install bitcoinlantern

alternatively:

pip3 install bitcoinlantern
```


## Running the tests

Coming soon 😬.


## Deployment

Simply add bitcoinlantern to your requirements.txt file


## Contribute

Please read [CONTRIBUTE.md](https://github.com/leonjohnson/bitcoinlantern/blob/master/contribute.md) for details on how you can contribute.


## Authors

**Leon Johnson** - I run the [Advancing Bitcoin Conference](https://www.advancingbitcoin.com) and website.


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* @jimmysong whose Programming Bitcoin (pb-exercises) code is the basis of the elliptic curve functionality.
* Everyone downloading this code
