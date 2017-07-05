from json import loads
from json import dumps

import httplib2

class brpc_reply(object):
    def __init__(self, d={}):
	self.result = d['result']
	self.error  = d['error']
	self.id     = d['id']

class btcrpc(object):
    def __init__(self, hostname='127.0.0.1',port='8332',username=None,password=None,ver='1.0'):
	self.http = httplib2.Http()
	self.hostname = hostname
	self.port     = port
	self.username = username
	self.password = password
	self.header   = {'Content-Type': 'text/plain'}
	self.version  = ver

	if self.username is not None and self.password is not None:
	    self.http.add_credentials(self.username, self.password)


    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # Support Functions to JSON RPC PROTOCOL
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
    def get_url(self):
	return 'http://%s:%s' % (self.hostname,self.port)

    def rpc_credentials(self, username=None,password=None):
	self.username = username
	self.password = password
	if self.username is not None and self.password is not None:
	    self.http.add_credentials(self.username, self.password)

    def doPost(self, url, body):
	return self.http.request(url,method='POST',headers=self.header,body=dumps(body))

    def jsonrpc(self, method, params=[]):
	body = {}
	
	if self.version == '1.0':
	    body['method'] = method
	    body['params'] = params
	    body['id']	   = method
	elif self.version == '1.1':
	    body['version'] = self.version
	    body['method'] = method
	    body['params'] = params
	    body['id']	   = method
	elif self.version == '2.0':
	    body['jsonrpc'] = self.version
	    body['method'] = method
	    body['params'] = params
	    body['id']	   = method

	if body is not {}:
	    response, content = self.doPost(self.get_url(),body)
	    if response['status'] == '200':
		return brpc_reply(loads(content))
	else:
	    return None

    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # Bitcon CLI Interface
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    def getinfo(self):
	'''
	    The getinfo RPC prints various information about the node and the network.
	'''
	return self.jsonrpc('getinfo')

    def getreceivedbyaddress(self,address,confirmations=1):
	'''
	    The getreceivedbyaddress RPC returns the total amount received by 
	    the specified address in transactions with the specified number of
	    confirmations. It does not count coinbase transactions.
	'''
	params = [address,confirmations]
	return self.jsonrpc('getreceivedbyaddress', params)

    def getpeerinfo(self):
	'''
	    The getpeerinfo RPC returns data about each connected network node.
	'''
	return self.jsonrpc('getpeerinfo')


    def getdifficulty(self):
	'''
	    The getdifficulty RPC
	'''
	return self.jsonrpc('getdifficulty')

    def getconnectioncount(self):
	'''
	    The getconnectioncount RPC returns the number of connections to other nodes.
	'''
	return self.jsonrpc('getconnectioncount')

    def getchaintips(self):
	'''
	    The getchaintips RPC returns information about the highest-height block (tip) of each local block chain.
	'''
	return self.jsonrpc('getchaintips')

    def getnetworkinfo(self):
	'''
	    The getnetworkinfo RPC returns information about the node's connection to the network.
	'''
	return self.jsonrpc('getnetworkinfo')

    def getbalance(self, account='*',confirmations=1,watchonly=True):
	'''
	    The getbalance RPC gets the balance in decimal bitcoins across all accounts or for a particular account.
	'''
	params = [account,confirmations,watchonly]
	return self.jsonrpc('getbalance', params)

    def importaddress(self, address, account='', rescan=True):
	'''
	    The importaddress RPC adds an address or pubkey script to the wallet without the associated 
	    private key, allowing you to watch for transactions affecting that address or pubkey 
	    script without being able to spend any of its outputs.
	'''
	params = [address,account,rescan]
	return self.jsonrpc('importaddress', params)

    def importprivkey(self,privatekey,account='',rescan=True):
	'''
	    The importprivkey RPC adds a private key to your wallet. The key should be formatted 
	    in the wallet import format created by the dumpprivkey RPC.
	'''
	params = [privatekey,account,rescan]
	return self.jsonrpc('importprivkey', params)


    def listtransactions(self,account,count=10,skip=0,watchonly=False):
	'''
	    The listtransactions RPC returns the most recent transactions that affect the wallet.
	'''
	params = [account,count,skip,watchonly]
	return self.jsonrpc('listtransactions',params)

