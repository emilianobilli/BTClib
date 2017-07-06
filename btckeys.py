from hashlib  import sha256
from hashlib  import new as hashn
from ecdsa    import SigningKey
from ecdsa    import SECP256k1
from binascii import hexlify
from os       import urandom


#------------------------------------------------------------------------
# Invervalo valido de numeros para generar la privkey
#------------------------------------------------------------------------
MAX = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
MIN = 0x1

#------------------------------------------------------------------------
# Alfabeto Base 58 Bitcoin
#------------------------------------------------------------------------
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class btckeysException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class btckeys(object):
    def __init__(self, pk=None):
	if pk is not None:
	    if type(pk).__name__ == 'str':
		if len(pk) < 64:
		    self.private_key = self.__class__.complete_hex_str(pk)
		elif len(pk) > 64:
		    raise btckeysException('Hex private key string is to long')
		if self.__class__.is_valid(pk):
		    self.private_key = pk
		else:
		    raise btckeysException('Invalid private key value')
	    else:
		raise btckeysException('Expect str and % is pased' % type(pk).__name__)
	    self.public_key  = None
	    self.get_public_key()
	else:
	    self.private_key = None
	    self.public_key  = None
    
    @staticmethod
    def complete_hex_str(pk):
	i = 64 - len(pk)
	p = ''
	while i > 0:
	    p = p + '0'
	    i = i - 1
	return p + pk

    @classmethod
    def from_integer(cls, i):
	if type(i).__name__ == 'int' or type(i).__name__ == 'long':
	    pkstr = hex(i)[2:]
	    if pkstr.endswith('L'):
		pkstr = pkstr[0:-1]
	    if cls.is_valid(pkstr):
	        return cls(cls.complete_hex_str(pkstr))
	    else:
	        # Too long
	        raise btckeysException('Argument int or long is Invalid')
	else:
	    raise btckeysException('Invalid datatype, expect int or long')

    @staticmethod
    def bytearray_to_base58(ba):
	output = ''
	x = int(hexlify(ba),base=16)
	while x > 0:
	    x,r = divmod(x,58)
	    output = output + B58[r]
	return output[::-1]

    @staticmethod
    def base58_to_bytearray(b58str):
	output = 0
	for c in b58str:
	    i = B58.index(c)
	    output = output * 58 + i
	#
	# Hex() convert the number to string 0x and the last char is L
	# because is a Long
	return bytearray.fromhex(hex(output)[2:-1])

    @staticmethod
    def is_valid(privkey):
	int_pk = int(privkey,base=16)
	if int_pk < MAX and int_pk >= MIN:
	    return True
	else:
	    return False

    @classmethod
    def from_random(cls):
        valid = False
	while not valid:
	    pk = sha256(urandom(64)).hexdigest()
	    valid = cls.is_valid(pk)
	return cls(pk)

    @classmethod
    def from_paraphrase(cls, paraphrase=''):
	if paraphrase != '':
	    digest = sha256(paraphrase)
	    if cls.is_valid(digest.hexdigest()):
		return cls(digest.hexdigest())
	    else:
		return None
	return None

    @classmethod
    def from_wif(cls,wif):
	ba = cls.base58_to_bytearray(wif)
	if ba[0] == 0x80:
	    check_1 = ba[len(ba)-4:]
	    check_2 =  sha256(sha256(ba[0:len(ba)-4]).digest()).digest()[0:4]
	    if check_1 == check_2:
		return cls(hexlify(ba[1:len(ba)-4]))
	    else:
		pass
	else:
	    pass

    def get_public_key(self):
	if self.private_key is not None and self.public_key is None:
	    self.public_key = hexlify(SigningKey.from_secret_exponent(int(self.private_key,base=16),SECP256k1).get_verifying_key().to_string())

    def to_addr(self):
	if self.private_key is not None:
	    # Genera la public key
	    if self.public_key is None:
		self.get_public_key()
	    tmp = b'\x04' + bytearray.fromhex(self.public_key)
	    ripemd160 = b'\x00' + bytearray(hashn('ripemd160',sha256(tmp).digest()).digest())
	    tmp = ripemd160 + bytearray(sha256(sha256(ripemd160).digest()).digest()[0:4])
	    return '1' + self.__class__.bytearray_to_base58(tmp)
	return ''

    def to_wif(self):
	if self.private_key is not None:
	    tmp = b'\x80' + bytearray.fromhex(self.private_key)
	    tmp = tmp + bytearray(sha256(sha256(tmp).digest()).digest()[0:4])
	    return self.__class__.bytearray_to_base58(tmp)
	return ''

if __name__ == '__main__':
    pk = btckeys.from_random()
    print pk.private_key
    print pk.to_wif()
    print pk.to_addr()


