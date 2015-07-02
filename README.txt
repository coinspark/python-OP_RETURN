python-OP_RETURN v2
===================
Simple Python commands and libraries for using OP_RETURNs in bitcoin transactions.

Copyright (c) Coin Sciences Ltd - http://coinsecrets.org/

MIT License (see headers in files)


REQUIREMENTS
------------
* Python 2.5 or later (including Python 3)
* Bitcoin Core 0.9 or later


BEFORE YOU START
----------------
Check the constant settings at the top of OP_RETURN.py.
If you just installed Bitcoin Core, wait for it to download and verify old blocks.
If using as a library, add 'from OP_RETURN import *' in your Python script file.


TO SEND A BITCOIN TRANSACTION WITH SOME OP_RETURN METADATA
----------------------------------------------------------

On the command line:

* python send-OP_RETURN.py <send-address> <send-amount> <metadata> <testnet (optional)>

  <send-address> is the bitcoin address of the recipient
  <send-amount> is the amount to send (in units of BTC)
  <metadata> is a hex string or raw string containing the OP_RETURN metadata
             (auto-detection: treated as a hex string if it is a valid one)
  <testnet> should be 1 to use the bitcoin testnet, otherwise it can be omitted

* Outputs an error if one occurred or the txid if sending was successful

* Wait a few seconds then check http://coinsecrets.org/ for your OP_RETURN transaction.

* Examples:

  python send-OP_RETURN.py 149wHUMa41Xm2jnZtqgRx94uGbZD9kPXnS 0.001 'Hello, blockchain!'
  python send-OP_RETURN.py 149wHUMa41Xm2jnZtqgRx94uGbZD9kPXnS 0.001 48656c6c6f2c20626c6f636b636861696e21
  python send-OP_RETURN.py mzEJxCrdva57shpv62udriBBgMECmaPce4 0.001 'Hello, testnet!' 1


As a library:

* OP_RETURN_send(send_address, send_amount, metadata, testnet=False)

  send_address is the bitcoin address of the recipient
  send_amount is the amount to send (in units of BTC)
  metadata is a string of raw bytes containing the OP_RETURN metadata
  testnet is whether to use the bitcoin testnet network (False if omitted)

* Returns: {'error': '<some error string>'}
       or: {'txid': '<sent txid>'}

* Examples

  OP_RETURN_send('149wHUMa41Xm2jnZtqgRx94uGbZD9kPXnS', 0.001, 'Hello, blockchain!')
  OP_RETURN_send('mzEJxCrdva57shpv62udriBBgMECmaPce4', 0.001, 'Hello, testnet!', True)



TO STORE SOME DATA IN THE BLOCKCHAIN USING OP_RETURNs
-----------------------------------------------------

On the command line:

* python store-OP_RETURN.py <data> <testnet (optional)>

  <data> is a hex string or raw string containing the data to be stored
         (auto-detection: treated as a hex string if it is a valid one)
  <testnet> should be 1 to use the bitcoin testnet, otherwise it can be omitted

* Outputs an error if one occurred or if successful, the txids that were used to store
  the data and a short reference that can be used to retrieve it using this library.

* Wait a few seconds then check http://coinsecrets.org/ for your OP_RETURN transactions.

* Examples:

  python store-OP_RETURN.py 'This example stores 47 bytes in the blockchain.'
  python store-OP_RETURN.py 'This example stores 44 bytes in the testnet.' 1
  
  
As a library:

* OP_RETURN_store(data, testnet=False)

  data is the string of raw bytes to be stored
  testnet is whether to use the bitcoin testnet network (False if omitted)
  
* Returns: {'error': '<some error string>'}
       or: {'txids': ['<1st txid>', '<2nd txid>', ...],
            'ref': '<ref for retrieving data>'}
           
* Examples:

  OP_RETURN_store('This example stores 47 bytes in the blockchain.')
  OP_RETURN_store('This example stores 44 bytes in the testnet.', True)



TO RETRIEVE SOME DATA FROM OP_RETURNs IN THE BLOCKCHAIN
-------------------------------------------------------

On the command line:

* python retrieve-OP_RETURN.py <ref> <testnet (optional)>

  <ref> is the reference that was returned by a previous storage operation
  <testnet> should be 1 to use the bitcoin testnet, otherwise it can be omitted
  
* Outputs an error if one occurred or if successful, the retrieved data in hexadecimal
  and ASCII format, a list of the txids used to store the data, a list of the blocks in
  which the data is stored, and (if available) the best ref for retrieving the data
  quickly in future. This may or may not be different from the ref you provided.
  
* Examples:

  python retrieve-OP_RETURN.py 356115-052075
  python retrieve-OP_RETURN.py 396381-059737 1
  
  
As a library:

* OP_RETURN_retrieve(ref, max_results=1, testnet=False)

  ref is the reference that was returned by a previous storage operation
  max_results is the maximum number of results to retrieve (in general, omit for 1)
  testnet is whether to use the bitcoin testnet network (False if omitted)

* Returns: {'error': '<some error string>'}
       or: {'data': '<raw binary data>',
            'txids': ['<1st txid>', '<2nd txid>', ...],
            'heights': [<block 1 used>, <block 2 used>, ...],
            'ref': '<best ref for retrieving data>',
            'error': '<error if data only partially retrieved>'}
           
           A value of 0 in the 'heights' array means some data is still in the mempool.      
           The 'ref' and 'error' elements are only present if appropriate.
                 
* Examples:

  OP_RETURN_retrieve('356115-052075')
  OP_RETURN_retrieve('396381-059737', 1, True)
  
  

VERSION HISTORY
---------------
v2.0.2 - 30 June 2015
* First port of php-OP_RETURN to Python