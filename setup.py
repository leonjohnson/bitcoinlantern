import setuptools


setuptools.setup(
		name='bitcoinlantern',
		description='A bitcoin and lightning library that focuses on wallets and rpc.',
		long_description= 'A small Bitcoin library that\'s delightfully easy to read and easy to use.',
		author='Leon Johnson',
		author_email='leon.johnson@me.com',
		url='https://github.com/leonjohnson/bitcoinlantern',
		version='0.1.4',
		packages = setuptools.find_packages(exclude=['contrib', 'docs', 'tests', 'examples']),
		classifiers=[
			"Programming Language :: Python :: 3",
			"License :: OSI Approved :: MIT License",
			"Operating System :: OS Independent",
		],
		python_requires='>=3',
		platforms = ['any'],
		keywords='bitcoin, wallet, BIP32, hd-wallet, python',
		package_data={'': ['AUTHORS', 'LICENSE']},
		install_requires=[
			'base58',
			'requests',
		]
		
	)