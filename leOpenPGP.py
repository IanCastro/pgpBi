import binascii
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
import base64


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

class ClassName(object):
	"""docstring for ClassName"""
	def __init__(self, arg):
		super(ClassName, self).__init__()
		self.arg = arg
		
class openPGP:
	# encodedFile = 'ac1562076d6c322e7478745a81a8444d4553534147450ad314549aadbc2b4bee2311e6b47ff06ada69b141b358'
	# encodedFile = binascii.unhexlify(encodedFile)
	def __init__(self, arg, arg2 = None):
		self.encodedFile = arg
		self.extraParam = arg2


	def toint(self, str256):
		return reduce(lambda x,y:x*256+ord(y), str256, 0)

	def int2str256(self, longInt):
		if longInt == 0:
			return chr(0)
		str = ''
		while longInt > 0:
			str += chr(longInt%256)
			longInt /= 256
		return str[::-1]

	def leMPI(self, p):
		length = (self.toint(self.encodedFile[p: p + 2]) + 7) / 8
		p += 2
		mpi = self.encodedFile[p: p + length]
		p += length
		return (p, mpi)

	def leMPId(self, p, data):
		length = (self.toint(data[p: p + 2]) + 7) / 8
		p += 2
		mpi = data[p: p + length]
		p += length
		return (p, mpi)
		
	def blockSize(self, algo):
		if algo == 7 or algo == 8 or algo == 9:
			return 16
		else:
			print'''#9.2.  Symmetric-Key Algorithms'''
			exit(1)

	def makeKey(self, salt, coded, bs, passphrase):
		#3.7.1.3.  Iterated and Salted S2K
		count = (16 + (coded & 15)) << ((coded >> 4) + 6);
		# print'count',count
		comb = salt+passphrase
		# print'comb',binascii.hexlify(comb)
		while len(comb) < count:
			comb += comb
		comb = comb[:count]

		hd = hashlib.sha1(comb).digest()
		return hd[:bs]

	def printgpg(self, p, t):
		print(binascii.hexlify(self.encodedFile[p:p+t]))

	def leSecretData(self, passphrase, symEncAlgo, salt, coded, encrData, IV):
		bs = self.blockSize(symEncAlgo)
		key = self.makeKey(salt, coded, bs, passphrase)
		encrData = encrData+chr(0)*4
		data = AES.new(key, AES.MODE_CFB, IV, segment_size = 128).decrypt(encrData)[:-4]

		#print'data',binascii.hexlify(data)
		p, dRSA = self.leMPId(0, data)
		p, pRSA = self.leMPId(p, data)
		p, qRSA = self.leMPId(p, data)
		p, uRSA = self.leMPId(p, data)
		#print'dRSA',binascii.hexlify(dRSA)
		#print'pRSA',binascii.hexlify(pRSA)
		#print'qRSA',binascii.hexlify(qRSA)
		#print'uRSA',binascii.hexlify(uRSA)
		if hashlib.sha1(data[:p]).digest() != data[p:]:
			print'passphrase incorrect'
		else:
			# print'pass'
			'''coment'''

		
		#print'sha1',hashlib.sha1(data[:p]).hexdigest()
		#print'sha1',binascii.hexlify(data[p:])


	def secretKeyPaket(self, p, pEnd):
		#5.5.3.  Secret-Key Packet Formats//tag == 5 or tag == 7
		p = self.publicKeyPaket(p)
		s2kConventions = ord(self.encodedFile[p])
		p += 1
		if s2kConventions == 254 or s2kConventions == 255:
			symEncAlgo = ord(self.encodedFile[p])
			# self.printgpg(p, 1)
			p += 1
			#9.2.  Symmetric-Key Algorithms
			s2k = ord(self.encodedFile[p])
			# self.printgpg(p, 1)
			p += 1
			#3.7.1.  String-to-Key (S2K) Specifier Types
			hashAlgo = ord(self.encodedFile[p])
			# self.printgpg(p, 1)
			p += 1
			salt = self.encodedFile[p: p + 8]
			# self.printgpg(p, 8)
			p += 8
			coded = ord(self.encodedFile[p])
			# self.printgpg(p, 1)
			p += 1
			bs = self.blockSize(symEncAlgo)
			IV = self.encodedFile[p: p + bs]
			# self.printgpg(p, bs)
			p += bs
			encrData = self.encodedFile[p: pEnd]
			p = pEnd

			self.leSecretData('this is a pass', symEncAlgo, salt, coded, encrData, IV)
			# key = self.makeKey(salt, coded, bs, 'this is a pass')
			# encrData = encrData+chr(0)*4
			# data = AES.new(key, AES.MODE_CFB, IV, segment_size = 128).decrypt(encrData)[:-4]
			# print'data',binascii.hexlify(data)

			# exit(0)
		return pEnd



			
	def publicKeyPaket(self, p):
		#5.5.2.  Public-Key Packet Formats//tag == 6 or tag == 14
		version = ord(self.encodedFile[p])
		p += 1
		# print('v',version)
		if version == 3:
			print'''5.5.2.  Public-Key Packet Formats //version 3'''
		elif version == 4:
			dateCreated = datetime.fromtimestamp(self.toint(self.encodedFile[p: p+4]))
			p += 4
			print(dateCreated.strftime('%H:%M:%S %d/%m/%Y'))
			publicKeyAlgo = ord(self.encodedFile[p])
			p += 1
			#9.1.  Public-Key Algorithms
			if publicKeyAlgo == 1 or publicKeyAlgo == 2 or publicKeyAlgo == 3:
				#rsa
				p, nRSA = self.leMPI(p)
				p, eRSA = self.leMPI(p)
				#print(eRSA, mpi)
			elif publicKeyAlgo == 16:
				print'''5.5.2.  Public-Key Packet Formats Elgamal public key'''
				#Elgamal
			elif publicKeyAlgo == 17:
				print'''5.5.2.  Public-Key Packet Formats DSA public key'''
				#DSA
			else:
				print('publicKeyAlgo',publicKeyAlgo,'not suported')
				exit(1)

		else:
			print 'Public key paket version must be 3 or 4'
			exit(1)
		return p

	def Public_Key_Encrypted_Session_Key_Packets(self, p):
		#5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
		version = ord(self.encodedFile[p])
		p += 1
		# print('v',version)
		if version == 3:
			keyId = self.encodedFile[p: p + 8]
			p += 8
			publicKeyAlgo = ord(self.encodedFile[p])
			p += 1
			#9.1.  Public-Key Algorithms
			if publicKeyAlgo == 1 or publicKeyAlgo == 2 or publicKeyAlgo == 3:
				#rsa
				p, mRSA = self.leMPI(p)


				dRSA = '154044aacf00149f8fc3988ef1a993625afd993d648c739129c8633def54662162388da2926210f694ffaeb1e6b128c9c616b07062aae0f932b4d80095e2fe693d21d6430b00393b875f506bc7dfaa73555e930677dfc4688ce73d4b5cdb6cc677c8324dfeccae1f64b7bc26f6e021009b376c5f5be999597db97826d72dc7cb8874484b3b7e8e5263fc3cbf442d0beb3e4fe7e8356cd3ddec0302811ba7f4cf73b3afd98b7f0bd9a93123edd52ebadb0b570fd5ecacc715386469d5666d0d0d53c7bfa325f060cd804d2946ec4d0ad1e99326a3a290ceeb4dd6f79fb8211a30db04764e5bd3bc0e1394b7faead134471df0d07b3179b68a07624385c03d3ff1'
				nRSA = '9fed7a4e822a2c4a44618c1aef09ec36ce64565663ea12d4f581c599378dfbf75e2401ade55b277be405b1a55a348431c3c7b11289a47a59cc0eb8180b0a6e09c68fb3b65e8c14dd419f8b35d1af23bb43fa12d0a76416c324c1151c17c68c5d8e66dc735367394808167c0b6fa2de3af25117d1cc069029d55fb266f4dcbcf27726dad9f323b7a79e8bdb874f9320074202d4d4209366bb6f9afea0bb9fa9f0d2f8c606e96cb71e8746bdd651b78754c95b96de0708aa87b121d5c5ab155591285ce95f9145b4d17496dbd63a9f50e3f7d8a4a0d9792686cdcaeb0aed5e3ce7232eb3a13527744ef107ee675fdca8a4b1556f3fa3bdfb4e0edd77c0fe46e16d'
				dRSA = binascii.unhexlify(dRSA)
				nRSA = binascii.unhexlify(nRSA)
				# print('mRSA', binascii.hexlify(mRSA))
				# print('dRSA', binascii.hexlify(dRSA))
				# print('nRSA', binascii.hexlify(nRSA))
				mRSA = self.toint(mRSA)
				dRSA = self.toint(dRSA)
				nRSA = self.toint(nRSA)
				MM = powMod(mRSA, dRSA, nRSA)
				MM = self.int2str256(MM)
				MM = MM[MM.find(chr(0)):]
				# print('sum', reduce(lambda x,y:x+ord(y), MM[2:-2], 0))
				# print('check', self.toint(MM[-2:]))
				if reduce(lambda x,y:x+ord(y), MM[2:-2], 0) == self.toint(MM[-2:]):
					self.algo = ord(MM[1])
					#print('algo', self.algo)
					self.key = MM[2:-2]
					#print('key', binascii.hexlify(self.key))

			elif publicKeyAlgo == 16:
				print'''5.5.2.  Public-Key Packet Formats Elgamal public key'''
				exit(1)
				#Elgamal
			elif publicKeyAlgo == 17:
				print'''5.5.2.  Public-Key Packet Formats DSA public key'''
				exit(1)
				#DSA
			else:
				print('publicKeyAlgo',publicKeyAlgo,'not suported')
				exit(1)

		else:
			print 'Public-Key Encrypted Session Key version must be 3'
			exit(1)
		return p

	def SymEncryptedIntegrityProtectedDataPacket(self, p, pEnd):
		#5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
		# self.printgpg(p,pEnd)
		version = ord(self.encodedFile[p])
		p += 1
		#print('v',version)
		if version == 1:
			encrData = self.encodedFile[p: pEnd]
			p = pEnd
			# key = '4bcb9206f7b3064d15f83c8f1399c4367a6bf57251ee1f5d2a19a4abcef34659'
			# key = binascii.unhexlify(key)
			if self.algo == 7 or self.algo == 8 or self.algo == 9:
				# print 'l',len(encrData)
				lack = 16 - len(encrData)%self.blockSize(self.algo)
				# print 'lack',lack
				if lack != 16:
					encrData += '0'*lack
					data = AES.new(self.key, AES.MODE_CFB, chr(0)*16, segment_size = 128).decrypt(encrData)[:-lack]
				else:
					data = AES.new(self.key, AES.MODE_CFB, chr(0)*16, segment_size = 128).decrypt(encrData)
			else :
				print'''Not Implemented yet'''
				exit(1)
			# print 'data full',binascii.hexlify(data)
			if data[14:16] == data[16:18]:
				#data = data[18:]
				print 'data fim',binascii.hexlify(data[:18]),binascii.hexlify(data[18:])
				openPGP(data[18:], data[:18]).ff()
		else:
			print 'Sym. Encrypted Integrity Protected Data Packet version must be 1'
			exit(1)
		return p

	def LiteralDataPacket(self, p, pEnd):
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
				print'''5.9.  Literal Data Packet (Tag 11)//for your eyes only'''
			dateCreated = datetime.fromtimestamp(self.toint(self.encodedFile[p: p+4]))
			p += 4
			# print(dateCreated.strftime('%H:%M:%S %d/%m/%Y'))
			literalData = self.encodedFile[p:pEnd]
			p = pEnd
			# print('literalData',literalData)
			print(fileName, dateCreated.strftime('%H:%M:%S %d/%m/%Y'), literalData)
		else:
			print "Literal Data Packet must be formatted with 'b', 't' or 'u'"
			exit(1)
		return p


	def ModificationDetectionCodePacket(self, p):
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
			print'Detected Modification on Packet'
			exit(1)
		else:
			'''coment'''
			# print'pass MDP'
			# print(binascii.hexlify(self.encodedFile[p:]))
			# print(binascii.hexlify(sha))
		# print('binascii.hexlify(self.encodedFile[:p])')
		# print(binascii.hexlify(self.encodedFile[:p]))
		# print(hashlib.sha1().hexdigest())
		# print(sha)
		return p+20

	def UserIDPacket(self, p, pEnd):
		# 5.11.  User ID Packet (Tag 13)
		return pEnd

	def leTag(self, tag, p, length):
		# print('tag', tag)
		if(tag == 5 or tag == 7):
			return self.secretKeyPaket(p, p+length)
		elif tag == 6 or tag == 14:
			return self.publicKeyPaket(p)
		elif tag == 1:
			return self.Public_Key_Encrypted_Session_Key_Packets(p)
		elif tag == 18:
			return self.SymEncryptedIntegrityProtectedDataPacket(p, p+length)
		elif tag == 11:
			return self.LiteralDataPacket(p, p+length)
		elif tag == 19:
			return self.ModificationDetectionCodePacket(p)
		elif tag == 13:
			return self.UserIDPacket(p, p+length)
		else:
			print('!tag', tag)
			print('!length', length)
			return p + length

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
		xxd = self.encodedFile.split('\n')
		p = 0
		while xxd[p].strip() != '':
			p += 1
		p += 1
		q = len(xxd) - 1
		while len(xxd[q]) == 0 or xxd[q][0] != '=':
			q -= 1

		self.encodedFile = base64.b64decode(''.join(xxd[p:q]))
		# print binascii.hexlify(self.encodedFile)

	def ff(self):
		# self.encodedFile = open("ml2.txt.decoded.gpg", "rb").read()
		if self.encodedFile[0] == '-':
			self.decodeAsc()
		p = 0
		while(p < len(self.encodedFile)):
			# print(p,len(self.encodedFile))
			pTag = ord(self.encodedFile[p])
			p += 1
			# print('pTag',pTag)
			one = pTag & 128#1<<7
			if not one:
				print 'the beggin of block must be 1'
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
					length = self.toint(self.encodedFile[p: p + 4])
					p += 4
				else:
					print'''4.2.2.4.  Partial Body Lengths'''
			else:
				tag = (pTag & 63) >> 2#(tag & (1<<6)-1) >> 2
				lenType = pTag & 3#(1<<2)-1
				#print('lenType',lenType)
				if lenType < 3:
					#length = reduce(lambda x,y:x*256+ord(y), self.encodedFile[p: p + (1<<lenType)], 0)
					length = self.toint(self.encodedFile[p: p + (1<<lenType)])
					p += (1<<lenType)
				else:
					print'''4.2.1.  Old Format Packet Lengths// 3 - The packet is of indeterminate length'''


			#print('one',one)
			#print('newFormat',newFormat)
			#print('tag',tag)
			#print('length',length)
			p = self.leTag(tag, p, length)

		# print()
		# print(p)
		# print(len(self.encodedFile))
		print'==',p == len(self.encodedFile)

# openPGP(open("ml2.txt.decoded.gpg", "rb").read()).ff()
ttt = '85010c03f7c1f4b58d60352a0108008dd909f507b10e2787c0a046ccbc3b81fca9267ab5d49065ada990789891a21246ea4bbdff21cd8d0bebba6160b7b5e964cc7ca69a02cd8a38333cc8e7c193c05810e9972c64eb170fb46481d82a8f8349a28f3391ab8cd79bd0c42c4dbb3a4c9f777275a62e218c9d8876463983c15c29e95f8962e04a9d581599478d78b5dd29394efafead8c683ad45c094dcce2426525c160ab87b1ef55b4343585657aac8d0477418f705dc77dfee0611c297e5b72ff9e858530885a37b634ed9fb6d4cebba46a937d3957f7d009107f3d1d90404c3f6481db9d4a626102abc36721c46b28841762a45f58330882d4f5e22989512daec1b8e89f867115caccb0de179783d24001805653862a53b4fef15a29427deed7b7e2940650e08a5e9fcc8cdeb03b0411e05dbf9ac2cc1a870aef75d30bc55992b3ab83bd8c5528819f6dc63100174ae7'
ttt = binascii.unhexlify(ttt)
# openPGP(ttt).ff()
# openPGP(open("ml2.txt.gpg", "rb").read()).ff()
openPGP(open("secretKey.asc", "rb").read()).ff()
