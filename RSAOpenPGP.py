from Crypto.Cipher import AES
import hashlib

import Util
from S2kOpenPGP import S2kOpenPGP
from OpenPGPExceptions import *

class RSAOpenPGP:
	def read(self, body):
		#5.5.2.  Public-Key Packet Formats//Tag 6 or Tag 14
		self.version = ord(body[0])
		p = 1
		if self.version == 3:
			print '''5.5.2.  Public-Key Packet Formats //version 3'''
			exit(1)
		elif self.version == 4:
			self.dateCreated = body[p: p+4]
			p += 4
			self.publicKeyAlgo = ord(body[p])
			p += 1
			#9.1.  Public-Key Algorithms
			if self.publicKeyAlgo == 1 or self.publicKeyAlgo == 2 or self.publicKeyAlgo == 3:
				#rsa
				p, self.nStrRSA = Util.leMPI(body, p)
				self.nRSA = Util.toint(self.nStrRSA)
				self.messegeLen = len(self.nStrRSA)
				p, self.eStrRSA = Util.leMPI(body, p)
				self.eRSA = Util.toint(self.eStrRSA)

				self.packet = chr(0x99) + Util.int2str256(p, 2) + body[:p]
				self.fingerPrint = hashlib.sha1(self.packet).digest()
				self.keyId = self.fingerPrint[-8:]

				self.subKeys = []
				self.readed = False

				if p == len(body):
					self.hasSecretData = False
				else:
					self.hasSecretData = True
					self.readSecret(body[p:])
			elif publicKeyAlgo == 16:
				#Elgamal
				print '''>>> 5.5.2.  Public-Key Packet Formats Elgamal public key'''
				p, pDSA = Util.leMPI(body, p)
				p, gDSA = Util.leMPI(body, p)
				p, yDSA = Util.leMPI(body, p)
				exit(1)
			elif publicKeyAlgo == 17:
				#DSA
				print '''>>> 5.5.2.  Public-Key Packet Formats DSA public key'''
				p, pDSA = Util.leMPI(body, p)
				p, qDSA = Util.leMPI(body, p)
				p, gDSA = Util.leMPI(body, p)
				p, yDSA = Util.leMPI(body, p)
				exit(1)
			else:
				print('publicKeyAlgo',publicKeyAlgo,'not suported')
				exit(1)
		else:
			print '>>> Public key paket version must be 3 or 4 <<<'
			exit(1)
		return self

	def readSecret(self, body):
		#5.5.3.  Secret-Key Packet Formats//Tag 5 or Tag 7
		self.s2kConventions = ord(body[0])
		p = 1
		if self.s2kConventions == 254 or self.s2kConventions == 255:
			self.symEncAlgo = ord(body[p])
			p += 1
			#9.2.  Symmetric-Key Algorithms

			self.s2k = S2kOpenPGP()
			p = self.s2k.read(body, p)

			bs = Util.blockSize(self.symEncAlgo)
			self.IV = body[p: p + bs]
			p += bs
			
			self.encrData = body[p:]

	def generate(self, passphrase):
		self.version = 4
		self.publicKeyAlgo = 1
		self.readed = True
		self.hasSecretData = True
		self.subKeys = []
		self.s2kConventions = 254#0xfe
		self.symEncAlgo = 7
		bs = Util.blockSize(self.symEncAlgo)

		while True:
			self.pRSA = nextPrime(Util.myRandInt((9<<1020), (11<<1020)-1))
			self.qRSA = nextPrime(Util.myRandInt((13<<1020), (15<<1020)-1))
			self.nRSA = self.pRSA*self.qRSA
			self.eRSA = 65537#0011010001
			self.uRSA = Util.invMod(self.pRSA, self.qRSA)
			if self.uRSA == 0:
				continue;
			self.dRSA = Util.invMod(self.eRSA, (self.pRSA-1)*(self.qRSA-1))
			if self.dRSA == 0:
				continue;
			break

		self.pStrRSA = Util.int2str256(self.pRSA, 0)
		self.qStrRSA = Util.int2str256(self.qRSA, 0)
		self.nStrRSA = Util.int2str256(self.nRSA, 0)
		self.eStrRSA = Util.int2str256(self.eRSA, 0)
		self.dStrRSA = Util.int2str256(self.dRSA, 0)
		self.uStrRSA = Util.int2str256(self.uRSA, 0)

		self.messegeLen = len(self.nStrRSA)
		self.dateCreated = Util.TIMENOW()#dateCreated

		self.s2k = S2kOpenPGP().generate()
		self.IV = Util.randOctets(bs)

		data = (Util.toMPI(self.dStrRSA)
			+ Util.toMPI(self.pStrRSA)
			+ Util.toMPI(self.qStrRSA)
			+ Util.toMPI(self.uStrRSA))
		data += hashlib.sha1(data).digest()

		symKey = self.s2k.makeKey(bs, passphrase)
		lack = bs - len(data)%bs

		self.encrData = AES.new(symKey, AES.MODE_CFB, self.IV, segment_size = 128).encrypt(data + ' '*lack)[:-lack]

		body = (chr(self.version)
			+ self.dateCreated
			+ chr(self.publicKeyAlgo)
			+ Util.toMPI(self.nStrRSA)
			+ Util.toMPI(self.eStrRSA))
		self.packet = chr(0x99) + Util.int2str256(len(body), 2) + body
		self.fingerPrint = hashlib.sha1(self.packet).digest()
		self.keyId = self.fingerPrint[-8:]
		return self

	def leSecretData(self, passphrase):
		if not self.hasSecretData:
			print '>>>>>>>>>>>>>>>>>>>> not has secret data <<<<<<<<<<<<<<<<<<<<'
			exit(1)

		bs = Util.blockSize(self.symEncAlgo)
		symKey = self.s2k.makeKey(bs, passphrase)
		lack = bs - len(self.encrData)%bs

		# 9.2.  Symmetric-Key Algorithms
		if self.symEncAlgo == 7:
			# AES with 128-bit key
			data = AES.new(symKey, AES.MODE_CFB, self.IV, segment_size = 128).decrypt(self.encrData + ' '*lack)[:-lack]
		else:
			print '''9.2.  Symmetric-Key Algorithms'''
			exit(1)

		p, self.dStrRSA = Util.leMPI(data, 0)
		p, self.pStrRSA = Util.leMPI(data, p)
		p, self.qStrRSA = Util.leMPI(data, p)
		p, self.uStrRSA = Util.leMPI(data, p)

		if hashlib.sha1(data[:p]).digest() != data[p:]:
			raise OpenPGPIncorrectException('passphrase', 'sha1', hashlib.sha1(data[:p]).digest(), data[p:])

		self.dRSA = Util.toint(self.dStrRSA)
		self.pRSA = Util.toint(self.pStrRSA)
		self.qRSA = Util.toint(self.qStrRSA)
		self.uRSA = Util.toint(self.uStrRSA)
		self.readed = True

	def decodeRSA(self, mRSA, passphrase):
		if not self.readed:
			self.leSecretData(passphrase)
		MM = Util.powMod(Util.toint(mRSA), self.dRSA, self.nRSA)
		return  Util.int2str256(MM, self.messegeLen)

	def encodeRSA(self, MM):
		mRSA = Util.powMod(Util.toint(MM), self.eRSA, self.nRSA)
		return  Util.int2str256(mRSA, self.messegeLen)

	def unsignRSA(self, MM):
		mRSA = Util.powMod(Util.toint(MM), self.eRSA, self.nRSA)
		return  Util.int2str256(mRSA, self.messegeLen)

	def signRSA(self, mRSA, passphrase):#nao testado
		if not self.readed:
			self.leSecretData(passphrase)
		MM = Util.powMod(Util.toint(mRSA), self.dRSA, self.nRSA)
		return  Util.int2str256(MM, self.messegeLen)

def nextPrime(x):
	while isCompSimple(x) or isCompMiller(x):
		x += 1
	return x

def isCompSimple(n):
	p = [2,3,5,7,11,13,17,19]
	for x in p:
		if n % x == 0:
			return n != x
	return False

def isCompMiller(n):
	if n < 4:
		return False
	m = n-1
	k = 0
	while m % 2 == 0:
		m //= 2
		k += 1
	for i in range(100):
		b = Util.myRandInt(2, n - 2)
		r = Util.powMod(b, m, n)
		if r == 1:
			continue
		for i in range(k):
			if r == n-1:
				break
			r = (r*r) % n
		else:
			return True
	return False
