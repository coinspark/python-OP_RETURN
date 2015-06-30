# retrieve-OP_RETURN.py
# 
# CLI wrapper for OP_RETURN.py to retrieve data from OP_RETURNs
#
# Copyright (c) Coin Sciences Ltd
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


import sys, string
from OP_RETURN import *


if len(sys.argv)<2:
	sys.exit(
'''Usage:
python retrieve-OP_RETURN.py <ref> <testnet (optional)>'''
	)

ref=sys.argv[1]

if len(sys.argv)>2:
	testnet=bool(sys.argv[2])
else:
	testnet=False

results=OP_RETURN_retrieve(ref, 1, testnet)

if 'error' in results:
	print('Error: '+results['error'])
	
elif len(results):
	for result in results:
		print("Hex: ("+str(len(result['data']))+" bytes)\n"+OP_RETURN_bin_to_hex(result['data'])+"\n")
		print("ASCII:\n"+re.sub(b'[^\x20-\x7E]', b'?', result['data']).decode('utf-8')+"\n")
		print("TxIDs: (count "+str(len(result['txids']))+")\n"+"\n".join(result['txids'])+"\n")
		print("Blocks:"+("\n"+("\n".join(map(str, result['heights'])))+"\n").replace("\n0\n", "\n[mempool]\n"))
		
		if 'ref' in result:
			print("Best ref:\n"+result['ref']+"\n")

		if 'error' in result:
			print("Error:\n"+result['error']+"\n")

else:
	print("No matching data was found")
