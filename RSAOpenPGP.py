from Crypto.Cipher import AES
import hashlib

import Util

class RSAOpenPGP:
	def __init__(self, fingerPrint, nRSA, eRSA, bodyStart, bodyEnd, dateCreated):
		# print('nrsa:',binascii.hexlify(publicKey[0]))
		# print('ersa:',binascii.hexlify(publicKey[1]))
		self.fingerPrint = fingerPrint
		self.nStrRSA = nRSA
		self.nRSA = Util.toint(nRSA)
		self.messegeLen = len(nRSA)
		self.eStrRSA = eRSA
		self.eRSA = Util.toint(eRSA)
		self.hasSecretData = False;
		self.readed = False;
		self.subKeys = [];
		self.bodyStart = bodyStart;
		self.bodyEnd = bodyEnd;
		self.dateCreated = dateCreated

	def insertSecretData(self, symEncAlgo, s2k, IV, encrData):
		self.symEncAlgo = symEncAlgo
		self.s2k = s2k
		self.IV = IV
		self.encrData = encrData
		self.hasSecretData = True;

	def leSecretData(self, passphrase):
		if not self.hasSecretData:
			print '>>>>>>>>>>>>>>>>>>>> not has secret data <<<<<<<<<<<<<<<<<<<<'
			exit(1)

		bs = Util.blockSize(self.symEncAlgo)
		
		symKey = self.s2k.makeKey(bs, passphrase)
		
		lack = bs - len(self.encrData)%bs
		# print 'lack',lack

		# 9.2.  Symmetric-Key Algorithms
		if self.symEncAlgo == 7:
			# AES with 128-bit key
			if lack != bs:
				self.encrData = self.encrData+chr(0)*lack
				data = AES.new(symKey, AES.MODE_CFB, self.IV, segment_size = 128).decrypt(self.encrData)[:-lack]
			else:
				data = AES.new(symKey, AES.MODE_CFB, self.IV, segment_size = 128).decrypt(self.encrData)
		else:
			print '''9.2.  Symmetric-Key Algorithms'''
			exit(1)


		#print 'data',binascii.hexlify(data)
		p, self.dStrRSA = Util.leMPI(data, 0)
		p, self.pStrRSA = Util.leMPI(data, p)
		p, self.qStrRSA = Util.leMPI(data, p)
		p, self.uStrRSA = Util.leMPI(data, p)
		#print 'dRSA',binascii.hexlify(dRSA)
		#print 'pRSA',binascii.hexlify(pRSA)
		#print 'qRSA',binascii.hexlify(qRSA)
		#print 'uRSA',binascii.hexlify(uRSA)
		# print 'ddddddddddddddddd',binascii.hexlify(data)
		# print 'ddddddddddddddddd',binascii.hexlify(data[p:])

		if hashlib.sha1(data[:p]).digest() != data[p:]:
			# print 'passphrase incorrect'
			print 'sha1',hashlib.sha1(data[:p]).hexdigest()
			print 'sha1',binascii.hexlify(data[p:])
			raise MyException('>>> passphrase incorrect <<<')

		# print binascii.hexlify(hashlib.sha1(data[:p]).digest())
		# print binascii.hexlify(data[p:])
		# print 'passphrase correct'


		self.dRSA = Util.toint(self.dStrRSA)
		self.pRSA = Util.toint(self.pStrRSA)
		self.qRSA = Util.toint(self.qStrRSA)
		self.uRSA = Util.toint(self.uStrRSA)
		self.readed = True;

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
