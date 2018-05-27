import binascii
import random
import time
import hashlib

myRandInt = random.SystemRandom().randint

def auxF(h, M, f):
	if h == 8:
		hashAlgo = hashlib.sha256
	elif h == 2:
		hashAlgo = hashlib.sha1
	else:
		print '>>> !hashAlgo <<<'
		exit(1)
	# M = binascii.unhexlify(M)
	# f = binascii.unhexlify(f)
	# print binascii.hexlify(f)
	for i in xrange(len(M)):
		for j in xrange(i):
			# print '?',hashAlgo(M[j: i]).hexdigest()
			if hashAlgo(M[j: i]).digest() == f:
				print 'ji:',j,i,hashAlgo(M[j: i]).hexdigest()
	print '!ji'

def auxF2(h, M, f):
	if h == 8:
		hashAlgo = hashlib.sha256
	elif h == 2:
		hashAlgo = hashlib.sha1
	else:
		print '>>> !hashAlgo <<<'
		exit(1)
	# M = binascii.unhexlify(M)
	# f = binascii.unhexlify(f)
	# print binascii.hexlify(f)
	for i in xrange(len(M)):
		print 'i', i, len(M)
		for j in xrange(i):
			for k in xrange(i, len(M)):
				for l in xrange(i, k):
					# print '?',hashAlgo(M[j: i]).hexdigest()
					if hashAlgo(M[j: i] + M[l: k]).digest() == f:
						print 'ji:',j,i,hashAlgo(M[j: i]).hexdigest()
	print '!ji'

def powMod(b, e, mod):
	#print('e', e)
	o = 1
	a = b
	while e > 0:
		if e%2 == 1:
			o = (o * a) % mod
		a = (a*a)%mod
		e //= 2
	return o

def blockSize(algo):
	# 9.2.  Symmetric-Key Algorithms
	if algo == 7 or algo == 8 or algo == 9:
		return 16
	else:
		print '''9.2.  Symmetric-Key Algorithms''', algo
		exit(1)

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
	return binascii.unhexlify("{0:0{1}x}".format(longInt, length*2));
	# if longInt == 0:
	# 	return chr(0)
	str = ''
	# while longInt > 0:
	for _ in range(length):
		str += chr(longInt%256)
		longInt /= 256
	return str[::-1]

def EME_PKCS1_v1_5_DECODE(EM):
	#13.1.2.  EME-PKCS1-v1_5-DECODE
	p = EM.find(chr(0), 1)
	if p <= 8 or EM[0] != chr(0) or EM[1] != chr(2):
		return ""
		print '>>>>>>>>>>>>>>>>>>>> EME-PKCS1-v1_5-DECODE decryption error <<<<<<<<<<<<<<<<<<<<'
		exit(1)
	return EM[p+1:]

def EME_PKCS1_v1_5_ENCODE(M, k):
	#13.1.1.  EME-PKCS1-v1_5-ENCODE
	psLen = k - len(M) - 3
	if psLen < 8:
		print '>>>>>>>>>>>>>>>>>>>> EME-PKCS1-v1_5-ENCODE message too long <<<<<<<<<<<<<<<<<<<<'
		exit(1)

	randCharNon0 = lambda : chr(myRandInt(1,255))
	PS = ''.join(randCharNon0() for i in range(psLen))
	return chr(0) + chr(2) + PS + chr(0) + M

def EMSA_PKCS1_v1_5(M, hashAlgo, length):
	#13.1.3.  EMSA-PKCS1-v1_5
	T = ASN_1_DER(hashAlgo)
	psLen = length - 3 - len(T) - len(M)
	if psLen < 8:
		print '>>>>>>>>>>>>>>>>>>>> EMSA-PKCS1-v1_5 intended encoded message length too short <<<<<<<<<<<<<<<<<<<<'
		exit(1)
	return chr(0) + chr(1) + chr(0xff)*psLen + chr(0) + T + M

def ASN_1_DER(hashAlgo):
	if hashAlgo == 8:
		return binascii.unhexlify('3031300d060960864801650304020105000420')
	else:
		print '''5.2.2.  Version 3 Signature Packet Format//The full hash prefixes'''
		exit(1)

def TIMENOW():
	if localTest:
		return '\x5a\x49\x96\x21'#int2str256(1514772001, 4)
	else:
		return int2str256(int(time.time()), 4)

def hashAlgo(algo):
	if algo == 8:
		return hashlib.sha256
	elif algo == 2:
		return hashlib.sha1
	else:
		print '''9.4.  Hash Algorithms''', algo
		exit(1)
