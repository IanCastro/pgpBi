import binascii
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
import base64
import zlib
import random

class MyException(Exception):
    pass

class Util:
	myRandInt = random.SystemRandom().randint
	random.seed(0)
	myRandInt = random.randint
	@staticmethod
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

	@staticmethod
	def blockSize(algo):
		if algo == 7 or algo == 8 or algo == 9:
			return 16
		else:
			print '''#9.2.  Symmetric-Key Algorithms'''
			exit(1)

	@staticmethod
	def toint(str256):
		return reduce(lambda x,y:x*256+ord(y), str256, 0)

	@staticmethod
	def SampleChecksum(data):
		return reduce(lambda x,y:(x+ord(y))%65536, data, 0)
	
	@staticmethod
	def leMPI(data, p):
		length = (Util.toint(data[p: p + 2]) + 7) / 8
		p += 2
		mpi = data[p: p + length]
		p += length
		return (p, mpi)
	
	@staticmethod
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
		return Util.int2str256(length, 2) + data[p:]
		

	@staticmethod
	def int2str256(longInt, length):
		if longInt == 0:
			return chr(0)
		str = ''
		# while longInt > 0:
		for _ in range(length):
			str += chr(longInt%256)
			longInt /= 256
		return str[::-1]

	@staticmethod
	def EME_PKCS1_v1_5_DECODE(EM):
		#13.1.2.  EME-PKCS1-v1_5-DECODE
		p = EM.find(chr(0), 1)
		if p <= 8 or EM[0] != chr(0) or EM[1] != chr(2):
			return ""
			print '>>>>>>>>>>>>>>>>>>>> EME-PKCS1-v1_5-DECODE decryption error <<<<<<<<<<<<<<<<<<<<'
			exit(1)
		return EM[p+1:]

	@staticmethod
	def EME_PKCS1_v1_5_ENCODE(M, k):
		#13.1.1.  EME-PKCS1-v1_5-ENCODE
		psLen = k - len(M) - 3
		if psLen < 8:
			print '>>>>>>>>>>>>>>>>>>>> EME-PKCS1-v1_5-ENCODE message too long <<<<<<<<<<<<<<<<<<<<'
			exit(1)

		randCharNon0 = lambda : chr(Util.myRandInt(1,255))
		PS = ''.join(randCharNon0() for i in range(psLen))
		return chr(0) + chr(2) + PS + chr(0) + M


class s2kOpenPGP:
	def read(self, data, p):
		self.version = ord(data[p])
		# self.printgpg(p, 1)
		p += 1
		#3.7.1.  String-to-Key (S2K) Specifier Types
		if self.version != 0 and self.version != 1 and self.version != 3:
			print '>>> self.version version must be 0, 1 or 3 <<<'
			exit(1)

		self.hashAlgo = ord(data[p])
		# self.printgpg(p, 1)
		p += 1

		if self.version == 1 or self.version == 3:
			self.salt = data[p: p + 8]
			# self.printgpg(p, 8)
			p += 8

		if self.version == 3:
			coded = ord(data[p])
			self.count = (16 + (coded & 15)) << ((coded >> 4) + 6)
			# self.printgpg(p, 1)
			p += 1
		return p

	def makeKey(self, bs, passphrase):
		#3.7.1.3.  Iterated and Salted S2K
		comb = self.salt+passphrase
		while len(comb) < self.count:
			comb += comb
		comb = comb[:self.count]

		if self.hashAlgo == 1:
			#MD5
			print '''s2k MD5'''
			exit(1)
		elif self.hashAlgo == 2:
			hd = hashlib.sha1(comb).digest()
		elif self.hashAlgo == 3:
			#RIPE-MD/160
			print '''s2k RIPE-MD/160'''
			exit(1)
		elif self.hashAlgo == 8:
			#SHA256
			print '''s2k SHA256'''
			exit(1)
		elif self.hashAlgo == 9:
			#SHA384
			print '''s2k SHA384'''
			exit(1)
		elif self.hashAlgo == 10:
			#SHA384
			print '''s2k SHA384'''
			exit(1)
		elif self.hashAlgo == 11:
			#SHA224
			print '''s2k SHA224'''
			exit(1)
		else:
			print('Hash Algorithms ', self.hashAlgo, 'not suported')
			exit(1)

		if len(hd) < bs:
			print '''need multiples hashes to make key'''
			print '''3.7.1.  String-to-Key (S2K) Specifier Types'''
			exit(1)
		return hd[:bs]

class secretKeyOpenPGP:
	def __init__(self, publicKey, symEncAlgo, s2k, encrData, IV):
		self.nRSA = Util.toint(publicKey[0])
		self.messegeLen = len(publicKey[0])
		self.eRSA = Util.toint(publicKey[1])
		self.symEncAlgo = symEncAlgo
		self.s2k = s2k
		self.IV = IV
		self.encrData = encrData
		self.readed = False;

	def leSecretData(self, passphrase):
		bs = Util.blockSize(self.symEncAlgo)
		
		symKey = self.s2k.makeKey(bs, passphrase)
		
		lack = bs - len(self.encrData)%bs
		# print 'lack',lack
		# if symEncAlgo == AES
		if lack != bs:
			self.encrData = self.encrData+chr(0)*lack
			data = AES.new(symKey, AES.MODE_CFB, self.IV, segment_size = 128).decrypt(self.encrData)[:-lack]
		else:
			data = AES.new(symKey, AES.MODE_CFB, self.IV, segment_size = 128).decrypt(self.encrData)

		#print 'data',binascii.hexlify(data)
		p, dRSA = Util.leMPI(data, 0)
		p, pRSA = Util.leMPI(data, p)
		p, qRSA = Util.leMPI(data, p)
		p, uRSA = Util.leMPI(data, p)
		#print 'dRSA',binascii.hexlify(dRSA)
		#print 'pRSA',binascii.hexlify(pRSA)
		#print 'qRSA',binascii.hexlify(qRSA)
		#print 'uRSA',binascii.hexlify(uRSA)
		if hashlib.sha1(data[:p]).digest() != data[p:]:
			# print 'passphrase incorrect'
			#print 'sha1',hashlib.sha1(data[:p]).hexdigest()
			#print 'sha1',binascii.hexlify(data[p:])
			raise MyException('>>> passphrase incorrect <<<')

		# print binascii.hexlify(hashlib.sha1(data[:p]).digest())
		# print binascii.hexlify(data[p:])
		# print 'passphrase correct'


		self.dRSA = Util.toint(dRSA)
		self.pRSA = Util.toint(pRSA)
		self.qRSA = Util.toint(qRSA)
		self.uRSA = Util.toint(uRSA)
		self.readed = True;

	def decodeRSA(self, mRSA, passphrase):
		if not self.readed:
			self.leSecretData(passphrase)
		MM = Util.powMod(Util.toint(mRSA), self.dRSA, self.nRSA)
		return  Util.int2str256(MM, self.messegeLen)

	def encodeRSA(self, MM):
		mRSA = Util.powMod(Util.toint(MM), self.eRSA, self.nRSA)
		return  Util.int2str256(mRSA, self.messegeLen)

class openPGP:
	#def __init__(self, arg, arg2 = None):
	def __init__(self):
		# self.encodedFile = arg
		# self.extraParam = arg2
		self.secretKeys = []
		self.publicKeys = []

	def printgpg(self, p, t):
		print(binascii.hexlify(self.encodedFile[p:p+t]))

	def read_secretKeyPaket(self, p, pEnd):
		#5.5.3.  Secret-Key Packet Formats//Tag 5 or Tag 7
		p = self.read_publicKeyPaket(p)
		s2kConventions = ord(self.encodedFile[p])
		p += 1
		if s2kConventions == 254 or s2kConventions == 255:
			symEncAlgo = ord(self.encodedFile[p])
			# self.printgpg(p, 1)
			p += 1
			#9.2.  Symmetric-Key Algorithms

			s2k = s2kOpenPGP()
			p = s2k.read(self.encodedFile, p)

			bs = Util.blockSize(symEncAlgo)
			IV = self.encodedFile[p: p + bs]
			# self.printgpg(p, bs)
			p += bs
			encrData = self.encodedFile[p: pEnd]
			p = pEnd

			secretKey = secretKeyOpenPGP(self.publicKeys[-1], symEncAlgo, s2k, encrData, IV)
			self.secretKeys.append(secretKey);
			# try:
			# 	secretKey.leSecretData('this is a pass')
			# except MyException as e:
			# 	print e
			# 	exit(1)
			#self.leSecretData('this is a pass', symEncAlgo, salt, coded, encrData, IV)
			# key = self.makeKey(salt, coded, bs, 'this is a pass')
			# encrData = encrData+chr(0)*4
			# data = AES.new(key, AES.MODE_CFB, IV, segment_size = 128).decrypt(encrData)[:-4]
			# print 'data',binascii.hexlify(data)

			# exit(0)
		return pEnd

	def read_publicKeyPaket(self, p):
		#5.5.2.  Public-Key Packet Formats//Tag 6 or Tag 14
		version = ord(self.encodedFile[p])
		p += 1
		# print('version',version)
		if version == 3:
			print '''5.5.2.  Public-Key Packet Formats //version 3'''
			exit(1)
		elif version == 4:
			dateCreated = datetime.fromtimestamp(Util.toint(self.encodedFile[p: p+4]))
			p += 4
			print('dateCreated', dateCreated.strftime('%H:%M:%S %d/%m/%Y'))
			publicKeyAlgo = ord(self.encodedFile[p])
			p += 1
			#9.1.  Public-Key Algorithms
			if publicKeyAlgo == 1 or publicKeyAlgo == 2 or publicKeyAlgo == 3:
				#rsa
				p, nRSA = Util.leMPI(self.encodedFile, p)
				p, eRSA = Util.leMPI(self.encodedFile, p)
				self.publicKeys.append((nRSA, eRSA));
				#print(eRSA, mpi)
			elif publicKeyAlgo == 16:
				#Elgamal
				print '''5.5.2.  Public-Key Packet Formats Elgamal public key'''
				exit(1)
			elif publicKeyAlgo == 17:
				#DSA
				print '''5.5.2.  Public-Key Packet Formats DSA public key'''
				exit(1)
			else:
				print('publicKeyAlgo',publicKeyAlgo,'not suported')
				exit(1)
		else:
			print '>>> Public key paket version must be 3 or 4 <<<'
			exit(1)
		return p

	def read_Public_Key_Encrypted_Session_Key_Packets(self, p):
		#5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
		version = ord(self.encodedFile[p])
		p += 1
		# print('version',version)
		if version == 3:
			keyId = self.encodedFile[p: p + 8]
			p += 8
			print 'keyId', binascii.hexlify(keyId)
			publicKeyAlgo = ord(self.encodedFile[p])
			p += 1
			#9.1.  Public-Key Algorithms
			if publicKeyAlgo == 1 or publicKeyAlgo == 2 or publicKeyAlgo == 3:
				#rsa
				p, mRSA = Util.leMPI(self.encodedFile, p)

				# dRSA = '154044aacf00149f8fc3988ef1a993625afd993d648c739129c8633def54662162388da2926210f694ffaeb1e6b128c9c616b07062aae0f932b4d80095e2fe693d21d6430b00393b875f506bc7dfaa73555e930677dfc4688ce73d4b5cdb6cc677c8324dfeccae1f64b7bc26f6e021009b376c5f5be999597db97826d72dc7cb8874484b3b7e8e5263fc3cbf442d0beb3e4fe7e8356cd3ddec0302811ba7f4cf73b3afd98b7f0bd9a93123edd52ebadb0b570fd5ecacc715386469d5666d0d0d53c7bfa325f060cd804d2946ec4d0ad1e99326a3a290ceeb4dd6f79fb8211a30db04764e5bd3bc0e1394b7faead134471df0d07b3179b68a07624385c03d3ff1'
				# nRSA = '9fed7a4e822a2c4a44618c1aef09ec36ce64565663ea12d4f581c599378dfbf75e2401ade55b277be405b1a55a348431c3c7b11289a47a59cc0eb8180b0a6e09c68fb3b65e8c14dd419f8b35d1af23bb43fa12d0a76416c324c1151c17c68c5d8e66dc735367394808167c0b6fa2de3af25117d1cc069029d55fb266f4dcbcf27726dad9f323b7a79e8bdb874f9320074202d4d4209366bb6f9afea0bb9fa9f0d2f8c606e96cb71e8746bdd651b78754c95b96de0708aa87b121d5c5ab155591285ce95f9145b4d17496dbd63a9f50e3f7d8a4a0d9792686cdcaeb0aed5e3ce7232eb3a13527744ef107ee675fdca8a4b1556f3fa3bdfb4e0edd77c0fe46e16d'
				# #dRSA e nRSA from private key packet
				# dRSA = binascii.unhexlify(dRSA)
				# nRSA = binascii.unhexlify(nRSA)

				# print('mRSA', binascii.hexlify(mRSA))
				# print('dRSA', binascii.hexlify(dRSA))
				# print('nRSA', binascii.hexlify(nRSA))
				# mRSA = Util.toint(mRSA)
				# dRSA = Util.toint(dRSA)
				# nRSA = Util.toint(nRSA)
				# MM = Util.powMod(mRSA, dRSA, nRSA)
				# MM = Util.int2str256(MM)

				for keys in self.secretKeys:
					MM = keys.decodeRSA(mRSA, 'this is a pass')
					# MM = self.secretKeys[0].decodeRSA(mRSA, 'this is a pass')
					# MM = MM[MM.find(chr(0)):]
					MM = Util.EME_PKCS1_v1_5_DECODE(MM)
					# print('sum', reduce(lambda x,y:x+ord(y), MM[2:-2], 0))
					# print('check', Util.toint(MM[-2:]))
					#x+ord(y) mod 65k
					if MM == "" or Util.SampleChecksum(MM[1:-2]) != Util.toint(MM[-2:]):
						# print 'MM',binascii.hexlify(MM)
						# print Util.SampleChecksum(MM[1:-2])
						# print Util.toint(MM[-2:])
						continue
						print '>>>>>>>>>>>>>>>>>>>> checksum of symmetric-key does not match <<<<<<<<<<<<<<<<<<<<'
						exit(1)
					self.symAlgo = ord(MM[0])
					#print('algo', self.symAlgo)
					self.symKey = MM[1:-2]# key to be used by the symmetric-key algorithm
					#print('self.symKey', binascii.hexlify(self.symKey))
					break
				else:
					print '>>>>>>>>>>>>>>>>>>>> checksum of symmetric-key does not match <<<<<<<<<<<<<<<<<<<<'
					exit(1)
			elif publicKeyAlgo == 16:
				print '''5.5.2.  Public-Key Packet Formats Elgamal public key'''
				exit(1)
				#Elgamal
			elif publicKeyAlgo == 17:
				print '''5.5.2.  Public-Key Packet Formats DSA public key'''
				exit(1)
				#DSA
			else:
				print('publicKeyAlgo',publicKeyAlgo,'not suported')
				exit(1)

		else:
			print '>>> Public-Key Encrypted Session Key version must be 3 <<<'
			exit(1)
		return p

	def write_Public_Key_Encrypted_Session_Key_Packets(self):
		#5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
		version = chr(3)
		self.encodedFile += version

		keyId = binascii.unhexlify("f7c1f4b58d60352a")
		self.encodedFile += keyId

		publicKeyAlgo = chr(1)
		self.encodedFile += publicKeyAlgo

		self.symKey = binascii.unhexlify("4bcb9206f7b3064d15f83c8f1399c4367a6bf57251ee1f5d2a19a4abcef34659")
		checkSum = Util.SampleChecksum(self.symKey)
		self.symAlgo = 9
		#MM = chr(self.symAlgo) + self.symKey + chr(checkSum/256) + chr(checkSum%256)
		MM = chr(self.symAlgo) + self.symKey + Util.int2str256(checkSum, 2)
		MM = Util.EME_PKCS1_v1_5_ENCODE(MM, self.secretKeys[1].messegeLen)
		mRSA = self.secretKeys[1].encodeRSA(MM)
		self.encodedFile += Util.toMPI(mRSA)

	def read_SymEncryptedIntegrityProtectedDataPacket(self, p, pEnd):
		#5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
		# self.printgpg(p,pEnd)
		version = ord(self.encodedFile[p])
		p += 1
		#print('version',version)
		if version == 1:
			encrData = self.encodedFile[p: pEnd]
			p = pEnd
			# key = '4bcb9206f7b3064d15f83c8f1399c4367a6bf57251ee1f5d2a19a4abcef34659'
			# key = binascii.unhexlify(key)
			if self.symAlgo == 7 or self.symAlgo == 8 or self.symAlgo == 9:
				# print 'l',len(encrData)
				bs = Util.blockSize(self.symAlgo)
				lack = bs - len(encrData)%bs
				# print 'lack',lack
				if lack != bs:
					encrData += '0'*lack
					data = AES.new(self.symKey, AES.MODE_CFB, chr(0)*bs, segment_size = 128).decrypt(encrData)[:-lack]
				else:
					data = AES.new(self.symKey, AES.MODE_CFB, chr(0)*bs, segment_size = 128).decrypt(encrData)
			else:
				print '''Not Implemented yet'''
				exit(1)
			# print 'data full',binascii.hexlify(data)
			if data[14:16] != data[16:18]:
				print '>>>>>>>>>>>>>>>>>>>> session key is incorrect <<<<<<<<<<<<<<<<<<<<'
				exit(1)
			#data = data[18:]
			print 'new openPGP Protected Data',binascii.hexlify(data[:18]),binascii.hexlify(data[18:])
			openPGP().ff(data[18:], data[:18])
		else:
			print '>>> Sym. Encrypted Integrity Protected Data Packet version must be 1 <<<'
			exit(1)
		return p

	def write_SymEncryptedIntegrityProtectedDataPacket(self):
		#5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
		version = chr(1)
		self.encodedFile += version

		IV = ''.join(chr(Util.myRandInt(0,255)) for i in range(16))
		IV += IV[-2:]

		data = IV + openPGP().ff2([11, 19], IV).encodedFile

		bs = Util.blockSize(self.symAlgo)
		lack = bs - len(data)%bs
		if lack != bs:
			data += '0'*lack
			encrData = AES.new(self.symKey, AES.MODE_CFB, chr(0)*bs, segment_size = 128).encrypt(data)[:-lack]
		else:
			encrData = AES.new(self.symKey, AES.MODE_CFB, chr(0)*bs, segment_size = 128).encrypt(data)

		self.encodedFile += encrData

	def read_LiteralDataPacket(self, p, pEnd):
		#5.9.  Literal Data Packet (Tag 11)
		formatted = self.encodedFile[p]
		p += 1
		# print('formatted',formatted)
		if formatted == 'b':
			fileNameLen = ord(self.encodedFile[p])
			p += 1
			fileName = self.encodedFile[p:p+fileNameLen]
			p += fileNameLen
			# print('fileName',fileName)
			if fileName == "_CONSOLE":
				print '''5.9.  Literal Data Packet (Tag 11)//for your eyes only'''
				#exit(1)
			if self.encodedFile[p: p+4] != chr(0)*4:
				dateCreated = datetime.fromtimestamp(Util.toint(self.encodedFile[p: p+4])).strftime('%H:%M:%S %d/%m/%Y')
			else:
				dateCreated = 'whithout date'
			p += 4
			# print(dateCreated.strftime('%H:%M:%S %d/%m/%Y'))
			literalData = self.encodedFile[p:pEnd]
			# self.encodedFile = self.encodedFile[:p] + 'N' + self.encodedFile[p+1:]
			p = pEnd
			# print('literalData',literalData)
			print('file:', fileName, dateCreated, literalData)
		else:
			print "Literal Data Packet must be formatted with 'b', 't' or 'u'"
			exit(1)
		return p

	def write_LiteralDataPacket(self, fileName):
		#5.9.  Literal Data Packet (Tag 11)
		formatted = 'b'
		self.encodedFile += formatted

		fileNameLen = chr(len(fileName))
		self.encodedFile += fileNameLen

		self.encodedFile += fileName

		date = chr(0)*4
		self.encodedFile += date

		literalData = open(fileName, "r").read()
		self.encodedFile += literalData

	def read_ModificationDetectionCodePacket(self, p):
		#5.14.  Modification Detection Code Packet (Tag 19)
		# tex = 'MESSAGE\n'
		# tex = binascii.unhexlify('ac1562076d6c322e7478745a81a8444d4553534147450a')
		# print(hashlib.sha1(tex).hexdigest())
		# tex = binascii.unhexlify('85010c03f7c1f4b58d60352a0108008dd909f507b10e2787c0a046ccbc3b81fca9267ab5d49065ada990789891a21246ea4bbdff21cd8d0bebba6160b7b5e964cc7ca69a02cd8a38333cc8e7c193c05810e9972c64eb170fb46481d82a8f8349a28f3391ab8cd79bd0c42c4dbb3a4c9f777275a62e218c9d8876463983c15c29e95f8962e04a9d581599478d78b5dd29394efafead8c683ad45c094dcce2426525c160ab87b1ef55b4343585657aac8d0477418f705dc77dfee0611c297e5b72ff9e858530885a37b634ed9fb6d4cebba46a937d3957f7d009107f3d1d90404c3f6481db9d4a626102abc36721c46b28841762a45f58330882d4f5e22989512daec1b8e89f867115caccb0de179783d24001805653862a53b4fef15a29427deed7b7e2940650e08a5e9fcc8cdeb03b0411e05dbf9ac2cc1a870aef75d30bc55992b3ab83bd8c5528819f6dc63100174ae7')
		# tex = ttt
		# tex = binascii.unhexlify('62a59b039fd0577cb0ff56c38652b977b977ac1562076d6c322e7478745a81a8444d4553534147450ad314549aadbc2b4bee2311e6b47ff06ada69b141b358')
		# print len(tex)
		# for i in xrange(len(tex)+1):
		# 	for j in xrange(i+1):
		# 		sha = hashlib.sha1(tex[j:i]).hexdigest()
		# 		print(sha)
		# 		if '549aadbc2b4bee2311e6b47ff06ada69b141b358' == sha:
		# 			print(i, j)
		# 			break
		# 	else:
		# 		continue
		# 	break
		# else:
		# 	print False
		sha = hashlib.sha1(self.extraParam + self.encodedFile[:p]).digest()
		if sha != self.encodedFile[p:]:
			# print binascii.hexlify(self.extraParam + self.encodedFile[:p])
			print '>>>>>>>>>>>>>>>>>>>> Detected Modification on Packet <<<<<<<<<<<<<<<<<<<<'
			# print binascii.hexlify(sha)
			# print binascii.hexlify(self.encodedFile[p:])
			exit(1)
		# print 'pass MDP'
		# print(binascii.hexlify(self.encodedFile[p:]))
		# print(binascii.hexlify(sha))

		# print('binascii.hexlify(self.encodedFile[:p])')
		# print(binascii.hexlify(self.encodedFile[:p]))
		# print(hashlib.sha1().hexdigest())
		# print(sha)
		return p+20

	def write_ModificationDetectionCodePacket(self):
		#5.14.  Modification Detection Code Packet (Tag 19)
		# print 'ModificationDetectionCodePacket', binascii.hexlify(self.extraParam + self.encodedFile + chr(20))
		sha = hashlib.sha1(self.extraParam + self.encodedFile + chr(20)).digest()
		self.encodedFile += sha

	def read_UserIDPacket(self, p, pEnd):
		# 5.11.  User ID Packet (Tag 13)
		userId = self.encodedFile[p:pEnd]
		print('userId',userId)
		return pEnd

	def SubPacket(self, p, pEnd):
		dataSet = {}
		while p != pEnd:
			stOctet = ord(self.encodedFile[p]);
			p += 1
			# print('stOctet',stOctet)
			if stOctet < 192:
				length = stOctet
			elif stOctet < 255:
				ndOctet = ord(self.encodedFile[p]);
				p += 1
				length = (stOctet - 192 << 8) + ndOctet + 192
			else:
				length = Util.toint(self.encodedFile[p: p + 4])
				p += 4
			subpacketType = ord(self.encodedFile[p]);
			subpacketData = self.encodedFile[p+1: p+length];
			p += length
			# subpacketData = binascii.hexlify(subpacketData)
			dataSet[subpacketType] = subpacketData
		return dataSet

	def read_SignaturePacket(self, p, pEnd):
		# 5.2.  Signature Packet (Tag 2)
		pv = p
		version = ord(self.encodedFile[p])
		p += 1
		print('version',version)
		if version == 3:
			print '''5.2.2.  Version 3 Signature Packet Format'''
			exit(1)
		elif version == 4:
			signatureType = ord(self.encodedFile[p])
			print('signatureType',signatureType)
			p += 1
			publicKeyAlgo = ord(self.encodedFile[p])
			print('publicKeyAlgo',publicKeyAlgo)
			p += 1
			hashAlgo = ord(self.encodedFile[p])
			print('hashAlgo',hashAlgo)
			p += 1
			hashedSubpacketLen = Util.toint(self.encodedFile[p: p+2])
			print('hashedSubpacketLen',hashedSubpacketLen)
			p += 2
			# hashedSubpacket = self.encodedFile[p: p+hashedSubpacketLen]
			# p += hashedSubpacketLen
			# print 'hashedSubpacket',binascii.hexlify(hashedSubpacket)
			hashedSubpacket = self.SubPacket(p, p+hashedSubpacketLen)
			p += hashedSubpacketLen
			print('hashedSubpacket', hashedSubpacket)
			hd = hashlib.sha1(self.encodedFile[pv:p]).hexdigest()
			print '>>>>>>>>>>>>>>',hd
			# print '>>>>>>>>>>>>>>',reduce(lambda x,y:(x+ord(y)), self.encodedFile[pv:p], 0)
			unhashedSubpacketLen = Util.toint(self.encodedFile[p: p+2])
			print('unhashedSubpacketLen',unhashedSubpacketLen)
			p += 2
			# unhashedSubpacket = self.encodedFile[p: p+unhashedSubpacketLen]
			# p += unhashedSubpacketLen
			# print 'unhashedSubpacket',binascii.hexlify(unhashedSubpacket)
			unhashedSubpacket = self.SubPacket(p, p+unhashedSubpacketLen)
			p += unhashedSubpacketLen
			print('unhashedSubpacket', unhashedSubpacket)
			signedHashValue = Util.toint(self.encodedFile[p: p+2])
			print('signedHashValue', signedHashValue)
			print('<<<<<<<<<<<<<<<<', hex(signedHashValue))
			p += 2
			while p != pEnd:
				p, mm = Util.leMPI(self.encodedFile, p)
				# print(mm,'mm')
		else:
			print '>>> Signature Packet version must be 3 or 4 <<<'
			exit(1)
		return p

	def read_CompressedDataPacket(self, p, pEnd):
		# 5.6.  Compressed Data Packet (Tag 8)
		compressAlgo = ord(self.encodedFile[p])
		p += 1
		#9.3.  Compression Algorithms
		if compressAlgo == 1:
			#zip
			decompressedFile = zlib.decompress(self.encodedFile[p: pEnd], -15)
			print 'new openPGP zip decompressedFile'
			openPGP().ff(decompressedFile)
		elif compressAlgo == 2:
			#zlib
			print '''9.3.  Compression Algorithms: zlib'''
			exit(1)
		elif compressAlgo == 3:
			#bzip2
			print '''9.3.  Compression Algorithms bzip2'''
			exit(1)
		else:
			print('compressAlgo',compressAlgo,'not suported')
			exit(1)
		return pEnd


	def readTag(self, tag, p, length):
		print('tag', tag)
		if tag == 5 or tag == 7:
			return self.read_secretKeyPaket(p, p+length)
		elif tag == 6 or tag == 14:
			return self.read_publicKeyPaket(p)
		elif tag == 1:
			return self.read_Public_Key_Encrypted_Session_Key_Packets(p)
		elif tag == 18:
			return self.read_SymEncryptedIntegrityProtectedDataPacket(p, p+length)
		elif tag == 11:
			return self.read_LiteralDataPacket(p, p+length)
		elif tag == 19:
			return self.read_ModificationDetectionCodePacket(p)
		elif tag == 13:
			return self.read_UserIDPacket(p, p+length)
		elif tag == 2:
			return self.read_SignaturePacket(p, p+length)
		elif tag == 8:
			return self.read_CompressedDataPacket(p, p+length)
		else:
			print('!tag', tag)
			print('!length', length)
			return p + length

	def writeTag(self, tag):
		if tag == 1:
			return self.write_Public_Key_Encrypted_Session_Key_Packets()
		elif tag == 18:
			return self.write_SymEncryptedIntegrityProtectedDataPacket()
		elif tag == 11:
			return self.write_LiteralDataPacket("file.txt")
		elif tag == 19:
			return self.write_ModificationDetectionCodePacket()
		else:
			print('!tag', tag)
			

	def crc24(self, octets):
		#6.1.  An Implementation of the CRC-24 in "C"
		crc = CRC24_INIT = 0xB704CEL
		CRC24_POLY = 0x1864CFBL
		for x in octets:
			crc ^= ord(x) << 16;
			for i in xrange(8):
				crc <<= 1;
				if (crc & 0x1000000):
					crc ^= CRC24_POLY;
		return crc

	def encodeAsc(self):
		crcFile = self.crc24(self.encodedFile)
		base64File = base64.b64encode(self.encodedFile)
		self.encodedFile = "-----BEGIN PGP MESSAGE-----\n\n"
		p = 0
		while p < len(base64File):
			self.encodedFile += base64File[p: p+64] + '\n'
			p += 64
		self.encodedFile += '=' + base64.b64encode(binascii.unhexlify(hex(crcFile)[2:-1])) + '\n'
		self.encodedFile += '-----END PGP MESSAGE-----\n'
		return self

	def decodeAsc(self):
		# p = 5
		# headers = {'BEGIN PGP MESSAGE',
		# 'BEGIN PGP PUBLIC KEY BLOCK',
		# 'BEGIN PGP PRIVATE KEY BLOCK',
		# 'BEGIN PGP MESSAGE, PART X/Y',
		# 'BEGIN PGP MESSAGE, PART X',
		# 'BEGIN PGP SIGNATURE'}
		# for h in headers:
		# 	if self.encodedFile[p: p+len(h)] == h:
		# 		# print h
		# 		p += len(h)+6
		stringFile = self.encodedFile.split('\n')
		p = 0
		while stringFile[p].strip() != '':
			p += 1
		p += 1
		q = len(stringFile) - 1
		while len(stringFile[q]) == 0 or stringFile[q][0] != '=':
			q -= 1

		self.encodedFile = base64.b64decode(''.join(stringFile[p:q]))
		crcFile = self.crc24(self.encodedFile)
		if Util.toint(base64.b64decode(stringFile[q][1:])) != crcFile:
			print '>>>>>>>>>>>>>>>>>>>> corrupted file <<<<<<<<<<<<<<<<<<<<'
			print '> crc24 on file',stringFile[q][1:]
			print '> crc24 calculeded',base64.b64encode(binascii.unhexlify(hex(crcFile)[2:-1]))
			exit(1)
		# print '=:',xxd[q]
		# print '=:',base64.b64decode(xxd[q][1:])
		# print '=:',binascii.hexlify(base64.b64decode(xxd[q][1:]))
		# print '===:',Util.toint(base64.b64decode(xxd[q][1:]))
		# print '===:',crcFile
		# # print binascii.hexlify(self.encodedFile)	
		# print 'crc:',hex(crcFile)[2:-1]
		# print 'crc:',base64.b64encode(hex(crcFile)[2:-1])
		# print 'crc2:',base64.b64encode(binascii.unhexlify(hex(crcFile)[2:-1]))
		return self

	def savefile(self, fileName):
		open(fileName, "wb").write(self.encodedFile)
		return self

	def len2NewFormat(self, length):
		if length < 192:
			return chr(length)
		elif length < 8383:
			length -= 192
			return chr((length>>8) + 192) + chr(length & 255)#chr(length & ((1<<8)-1))
		elif length < (1<<32):
			return chr(255) + int2str256(length, 4)
		else:
			print '''4.2.2.4.  Partial Body Lengths'''
			exit(1)

	def ff2(self, arg, arg2 = None):
		self.encodedFile = ''
		self.extraParam = arg2

		for tag in arg:
			self.encodedFile += chr(192 + tag)#chr((1<<7) + (1<<6) + tag)
			p = len(self.encodedFile)
			self.writeTag(tag)
			self.encodedFile = self.encodedFile[:p] + self.len2NewFormat(len(self.encodedFile[p:])) + self.encodedFile[p:]
		return self

	def ff(self, arg, arg2 = None):
		self.encodedFile = arg
		self.extraParam = arg2
		# self.encodedFile = open("ml2.txt.decoded.gpg", "rb").read()
		if self.encodedFile[0] == '-':
			self.decodeAsc()
		# self.encodeAsc()
		# self.decodeAsc()
		p = 0
		while(p < len(self.encodedFile)):
			# print(p,len(self.encodedFile))
			pTag = ord(self.encodedFile[p])
			p += 1
			# print('pTag',pTag)
			one = pTag & 128#1<<7
			if not one:
				print '>>>>>>>>>>>>>>>>>>>> the beggin of block must be 1 <<<<<<<<<<<<<<<<<<<<'
				exit(1)
			newFormat = pTag & 64#1<<6
			if newFormat:
				tag = pTag & 63#(1<<6)-1
				stOctet = ord(self.encodedFile[p]);
				p += 1
				# print('stOctet',stOctet)
				if stOctet < 192:
					length = stOctet
				elif stOctet < 224:
					ndOctet = ord(self.encodedFile[p]);
					p += 1
					length = (stOctet - 192 << 8) + ndOctet + 192
				elif stOctet == 255:
					#length = reduce(lambda x,y:x*256+ord(y), self.encodedFile[p: p + 4], 0)
					length = Util.toint(self.encodedFile[p: p + 4])
					p += 4
				else:
					print '''4.2.2.4.  Partial Body Lengths'''
					exit(1)
			else:
				tag = (pTag & 63) >> 2#(pTag & (1<<6)-1) >> 2
				lenType = pTag & 3#(1<<2)-1
				#print('lenType',lenType)
				if lenType < 3:
					#length = reduce(lambda x,y:x*256+ord(y), self.encodedFile[p: p + (1<<lenType)], 0)
					length = Util.toint(self.encodedFile[p: p + (1<<lenType)])
					p += (1<<lenType)
				else:
					#print '''4.2.1.  Old Format Packet Lengths// 3 - The packet is of indeterminate length'''
					#exit(1)
					length = len(self.encodedFile) - p

			#print('one',one)
			#print('newFormat',newFormat)
			#print('tag',tag)
			#print('length',length)
			p = self.readTag(tag, p, length)

		# print()
		# print(p)
		# print(len(self.encodedFile))
		print '==',p == len(self.encodedFile)

		# self.encodeAsc()
		# print self.encodedFile
		return self

# openPGP(open("ml2.txt.decoded.gpg", "rb").read()).ff()
ttt = '85010c03f7c1f4b58d60352a0108008dd909f507b10e2787c0a046ccbc3b81fca9267ab5d49065ada990789891a21246ea4bbdff21cd8d0bebba6160b7b5e964cc7ca69a02cd8a38333cc8e7c193c05810e9972c64eb170fb46481d82a8f8349a28f3391ab8cd79bd0c42c4dbb3a4c9f777275a62e218c9d8876463983c15c29e95f8962e04a9d581599478d78b5dd29394efafead8c683ad45c094dcce2426525c160ab87b1ef55b4343585657aac8d0477418f705dc77dfee0611c297e5b72ff9e858530885a37b634ed9fb6d4cebba46a937d3957f7d009107f3d1d90404c3f6481db9d4a626102abc36721c46b28841762a45f58330882d4f5e22989512daec1b8e89f867115caccb0de179783d24001805653862a53b4fef15a29427deed7b7e2940650e08a5e9fcc8cdeb03b0411e05dbf9ac2cc1a870aef75d30bc55992b3ab83bd8c5528819f6dc63100174ae7'
ttt = binascii.unhexlify(ttt)
# openPGP(ttt).ff()
# openPGP(open("secretKey.asc", "rb").read()).ff()
# print('---------------')
# openPGP(open("ml2.txt.gpg", "rb").read()).ff()
# sk = openPGP().ff(open("secretKey.asc", "rb").read()).ff(open("ml2.txt.gpg", "rb").read()).secretKeys
# for x in sk:
# 	print x.nRSA
# 	print x.pRSA
# 	print x.qRSA
# 	print x.eRSA
# 	print x.dRSA
# 	print x.uRSA
# 	print ''
# 	print x.symEncAlgo
# 	print x.count
# 	print binascii.hexlify(x.salt)
# 	print binascii.hexlify(x.IV)
# 	print binascii.hexlify(x.key)
# 	print ''
# 	print ''

# openPGP(open("compressZip.gpg", "rb").read()).ff()
# print openPGP(open("ml2.txt.gpg", "rb").read()).encodeAsc().encodedFile
# print openPGP(open("m.txt.asc", "rb").read()).ff().encodeAsc().encodedFile
# print openPGP(open("m.txt.asc", "rb").read()).ff().ff()
# openPGP(open("Example.asc", "rb").read()).ff()
# print binascii.hexlify(open("file.txt", "r").read())

secretKeyFile = open("secretKey.asc", "rb").read()
messageFile = open("ml2.txt.gpg", "rb").read()
# openPGP().ff(secretKeyFile).ff(messageFile)
print openPGP().ff(secretKeyFile).ff2([1, 18]).encodeAsc().savefile("file.txt.asc").encodedFile
openPGP().ff(secretKeyFile).ff(open("file.txt.asc", "rb").read())
