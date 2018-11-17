import binascii
import random
import time
import hashlib

myRandInt = random.SystemRandom().randint

localTest = False
if localTest:
	random.seed(0)
	myRandInt = random.randint

def powMod(b, e, mod):
	o = 1
	a = b
	while e > 0:
		if e%2 == 1:
			o = (o * a) % mod
		a = (a*a)%mod
		e //= 2
	return o

def invMod(b, mod):
	x, y, g = gcdE(b, mod)
	return (x+mod)%mod if g == 1 else 0

def gcdE(a, b):
	x0, y0 = 1, 0
	x1, y1 = 0, 1
	while b != 0:
		x0, x1 = x1, x0 - x1*(a//b)
		y0, y1 = y1, y0 - y1*(a//b)
		a, b = b, a%b
	return x0, y0, a

def blockSize(algo):
	# 9.2.  Symmetric-Key Algorithms
	if algo == 7 or algo == 8 or algo == 9:
		return 16
	else:
		raise OpenPGPException('9.2. Symmetric-Key Algorithms: ' + algo)

def toint(str256):
	return reduce(lambda x,y:x*256+ord(y), str256, 0)

def SampleChecksum(data):
	return reduce(lambda x,y:(x+ord(y))%65536, data, 0)

def leMPI(data, p):
	length = (toint(data[p: p + 2]) + 7) / 8
	p += 2
	mpi = data[p: p + length]
	p += length
	return (p, mpi)

def toMPI(data):
	length = len(data)*8
	p = 0
	while data[p] == chr(0):
		p += 1
		length -= 8
	aux = 128
	while aux > ord(data[p]):
		aux /= 2
		length -= 1
	return int2str256(length, 2) + data[p:]
	
def int2str256(longInt, length):
	if length == 0:
		s = "{0:x}".format(longInt)
		if len(s) % 2 == 1:
			s = '0' + s
	else:
		s = "{0:0{1}x}".format(longInt, length*2)
	return binascii.unhexlify(s)

def EME_PKCS1_v1_5_DECODE(EM):
	#13.1.2.  EME-PKCS1-v1_5-DECODE
	p = EM.find(chr(0), 1)
	if p <= 8 or EM[0] != chr(0) or EM[1] != chr(2):
		raise OpenPGPException('>>> EME-PKCS1-v1_5-DECODE decryption error <<<')
	return EM[p+1:]

def EME_PKCS1_v1_5_ENCODE(M, k):
	#13.1.1.  EME-PKCS1-v1_5-ENCODE
	psLen = k - len(M) - 3
	if psLen < 8:
		raise OpenPGPException('>>> EME-PKCS1-v1_5-ENCODE message too long <<<')
	PS = ''.join(chr(myRandInt(1,255)) for i in range(psLen))
	return chr(0) + chr(2) + PS + chr(0) + M

def EMSA_PKCS1_v1_5(M, hashAlgo, length):
	#13.1.3.  EMSA-PKCS1-v1_5
	T = ASN_1_DER(hashAlgo)
	psLen = length - 3 - len(T) - len(M)
	if psLen < 8:
		raise OpenPGPException('>>> EMSA-PKCS1-v1_5 intended encoded message length too short <<<')
	return chr(0) + chr(1) + chr(0xff)*psLen + chr(0) + T + M

def ASN_1_DER(hashAlgo):
	if hashAlgo == 8:
		return binascii.unhexlify('3031300d060960864801650304020105000420')
	else:
		raise OpenPGPException('5.2.2. Version 3 Signature Packet Format: ' + hashAlgo)

def TIMENOW():
	if localTest:
		return '\x5a\x49\x96\x21'
	else:
		return int2str256(int(time.time()), 4)

def hashAlgo(algo):
	if algo == 8:
		return hashlib.sha256
	elif algo == 2:
		return hashlib.sha1
	else:
		raise OpenPGPException('9.4. Hash Algorithms: ' + algo)

def display(msg, str256):
	print msg + ':', binascii.hexlify(str256)

def randOctets(n):
	return ''.join(chr(myRandInt(0,255)) for i in range(n))
