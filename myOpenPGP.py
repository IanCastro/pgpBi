import binascii
from Crypto.Cipher import AES
from datetime import datetime
import hashlib
import base64
import zlib
import time
from getpass import getpass
import os.path
import logging

import Util
from RSAOpenPGP import RSAOpenPGP
from OpenPGPExceptions import *

import testMyOpenPGP

class myOpenPGP:
	def __init__(self):
		self.asymmetricKeys = []
		self.keyId = ''

	def start(self):
		'''
			.generateKeyRSA("myUser <my@user.com>", 'this is a pass')	-g rsa username e@mail.com pass
			.readFile(open("euSign.gpg", "rb").read())					-r file.gpg
			.savePublicKey("user", "myPublKey")							-pk username -a -o output -c zip
			.savePrivateKey("", "genSecrKey", True)						-sk username -a -o output -c zip
			.encrypt("file.txt", "my@user.com", "euEncript", True)		-e file username -a -o output -c zip
			.signFile("file2.txt", "my@user.com", "euSign")				-s file username -a -o output -c zip
		'''
		while True:
			try:
				commandList = raw_input("Enter the command:").split(" ")
				commandList = filter(lambda x: x != '', commandList)
				cLen = len(commandList)
				if cLen == 0:
					continue
				command = commandList[0].lower()

				if command == 'exit':
					break;
				elif command == 'generatekey' or command == '-g':
					algo = raw_input("Algorithm?").lower() if cLen <= 1 else commandList[1]
					if algo != 'rsa':
						print'Only RSA Avaliable'
						continue
					name = raw_input("User Name?") if cLen <= 2 else commandList[2]
					email = raw_input("User E-mail?") if cLen <= 3 else commandList[3]
					passphrase = getpass("Passphase?") if cLen <= 4 else commandList[4]

					self.generateKeyRSA(name + " <" + email + ">", passphrase)
				elif command == 'readfile' or command == '-r':
					fileName = raw_input("File Name?") if cLen <= 1 else commandList[1]
					if os.path.isfile(fileName):
						self.readFile(open(fileName, "rb").read())
					else:
						print fileName, "not is a valid file."
						continue
				else:
					if command == 'encrypt' or command == '-e' or command == 'sign' or command == '-s':
						inputFile = commandList[1]
						if not os.path.isfile(inputFile):
							print inputFile, "not is a valid file"
							continue
						p = 2
					elif command == 'export-key' or command == '-pk' or command == 'export-secret-key' or command == '-sk':
						p = 1
					else:
						raise Exception('command ' + command + ' is not valid')

					user = ''
					if commandList[p][0] != '-':
						user = commandList[p]
						p += 1

					armor = False
					outputFile = ''
					compress = ''
					passphrase = ''
					confirm = True
					while p < cLen:
						if commandList[p] == '-a' or commandList[p] == '--armor':
							armor = True
							p += 1
						elif commandList[p] == '-o' or commandList[p] == '--output':
							outputFile = commandList[p+1]
							if outputFile.endswith('.gpg') or outputFile.endswith('.asc'):
								outputFile = outputFile[: -4]
							p += 2
						elif commandList[p] == '-c' or commandList[p] == '--compress':
							compress = commandList[p+1]
							p += 2
						elif commandList[p] == '-p' or commandList[p] == '--pass':
							passphrase = commandList[p+1]
							p += 2
						elif commandList[p] == '-i' or commandList[p] == '--ignore':
							confirm = False
							p += 1
						else:
							raise Exception('option ' + commandList[p] + ' is not valid')

					if command == 'encrypt' or command == '-e':
						self.encrypt(inputFile, user, outputFile, armor, confirm)
					elif command == 'sign' or command == '-s':
						self.signFile(inputFile, user, outputFile, passphrase, armor, confirm)
					elif command == 'export-key' or command == '-pk':
						self.savePublicKey(user, outputFile, passphrase, armor, confirm)
					elif command == 'export-secret-key' or command == '-sk':
						self.savePrivateKey(user, outputFile, passphrase, armor, confirm)
			except Exception as e:
				print e
				logging.exception("Something awful happened!")

	def setAsymmetricKeys(self, asymmetricKeys):
		self.asymmetricKeys = asymmetricKeys
		return self

	def generateKeyRSA(self, userId, passphrase):
		print 'generateKeyRSA'
		asymmetricKey = RSAOpenPGP().generate(passphrase)
		asymmetricKey.userId = userId
		asymmetricKey.subKeys.append(RSAOpenPGP().generate(passphrase))
		self.asymmetricKeys.append(asymmetricKey)
		return self

	def write_secretKeyPaket(self, keyIndex = -1, subKeyIndex = None):
		#5.5.3.  Secret-Key Packet Formats//Tag 5 or Tag 7
		return (self.write_publicKeyPaket(keyIndex, subKeyIndex)
			+ chr(self.asymSubKey.s2kConventions)
			+ chr(self.asymSubKey.symEncAlgo)
			+ self.asymSubKey.s2k.packet
			+ self.asymSubKey.IV
			+ self.asymSubKey.encrData)

	def write_publicKeyPaket(self, keyIndex = -1, subKeyIndex = None):
		#5.5.2.  Public-Key Packet Formats//Tag 6 or Tag 14
		self.asymKey = self.asymmetricKeys[keyIndex]
		self.asymSubKey = self.asymKey.subKeys[subKeyIndex] if subKeyIndex != None else self.asymKey

		return (chr(self.asymSubKey.version)
			+ self.asymSubKey.dateCreated
			+ chr(self.asymSubKey.publicKeyAlgo)
			+ Util.toMPI(self.asymSubKey.nStrRSA)
			+ Util.toMPI(self.asymSubKey.eStrRSA))

	def allKeys(self):
		for asymKey in self.asymmetricKeys:
			yield asymKey
			for asymSubKey in asymKey.subKeys:
				yield asymSubKey

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

				# for asymKey in self.asymmetricKeys:
				numTry = 0
				for asymKey in self.allKeys():
					if asymKey.keyId != keyId:
						continue
					numTry = numTry + 1
					MM = asymKey.decodeRSA(mRSA, 'this is a pass')
					MM = Util.EME_PKCS1_v1_5_DECODE(MM)
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
					if numTry > 0:
						print '>>>>>>>>>>>>>>>>>>>> checksum of symmetric-key does not match <<<<<<<<<<<<<<<<<<<<'
						exit(1)
					print 'self.keyId',binascii.hexlify(keyId)
					print '>>> not has the key for this criptografy, len(self.asymmetricKeys)',len(self.asymmetricKeys)
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

		self.symKey = binascii.unhexlify("4bcb9206f7b3064d15f83c8f1399c4367a6bf57251ee1f5d2a19a4abcef34659")#generate a new key
		checkSum = Util.SampleChecksum(self.symKey)
		self.symAlgo = 9

		MM = chr(self.symAlgo) + self.symKey + Util.int2str256(checkSum, 2)
		MM = Util.EME_PKCS1_v1_5_ENCODE(MM, self.asymKey.messegeLen)
		mRSA = self.asymKey.encodeRSA(MM)

		return (version
			+ self.asymKey.keyId
			+ chr(self.asymKey.publicKeyAlgo)
			+ Util.toMPI(mRSA))

	def read_SymEncryptedIntegrityProtectedDataPacket(self, p, pEnd):
		#5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
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
				data = AES.new(self.symKey, AES.MODE_CFB, chr(0)*bs, segment_size = 128).decrypt(encrData + ' '*lack)[:-lack]
			else:
				print '''Not Implemented yet'''
				exit(1)
			# print 'data full',binascii.hexlify(data)
			if data[14:16] != data[16:18]:
				print '>>>>>>>>>>>>>>>>>>>> session key is incorrect <<<<<<<<<<<<<<<<<<<<'
				exit(1)
			#data = data[18:]
			print 'new myOpenPGP Protected Data',binascii.hexlify(data[:18]),binascii.hexlify(data[18:])
			myOpenPGP().setAsymmetricKeys(self.asymmetricKeys).readFile(data[18:], data[:18])
		else:
			print '>>> Sym. Encrypted Integrity Protected Data Packet version must be 1 <<<'
			exit(1)
		return p

	def write_SymEncryptedIntegrityProtectedDataPacket(self, tags):
		#5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
		version = chr(1)

		IV = ''.join(chr(Util.myRandInt(0,255)) for i in range(16))
		IV += IV[-2:]

		data = IV + myOpenPGP().writeFile(tags, IV).encodedFile

		bs = Util.blockSize(self.symAlgo)
		lack = bs - len(data)%bs
		encrData = AES.new(self.symKey, AES.MODE_CFB, chr(0)*bs, segment_size = 128).encrypt(data + ' '*lack)[:-lack]

		return version + encrData

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
			self.paketStart = p
			self.paketEnd = pEnd
			literalData = self.encodedFile[p:pEnd]
			# self.encodedFile = self.encodedFile[:p] + 'N' + self.encodedFile[p+1:]
			p = pEnd
			# print('literalData',literalData)
			print 'file:', (fileName, dateCreated, literalData)
		else:
			print "Literal Data Packet must be formatted with 'b', 't' or 'u'"
			exit(1)
		return p

	def write_LiteralDataPacket(self, fileName):
		#5.9.  Literal Data Packet (Tag 11)
		formatted = 'b'

		fileNameLen = chr(len(fileName))

		date = chr(0)*4

		self.literalData = open(fileName, "r").read()

		return (formatted
			+ fileNameLen
			+ fileName
			+ date
			+ self.literalData)

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
		return sha

	def read_UserIDPacket(self, p, pEnd):
		# 5.11.  User ID Packet (Tag 13)
		self.asymKey.userId = self.encodedFile[p:pEnd]
		print 'userId:', self.asymKey.userId
		return pEnd

	def write_UserIDPacket(self):
		# 5.11.  User ID Packet (Tag 13)
		return self.asymKey.userId

	def leSubPacket(self, p, pEnd):
		dataSet = {}
		while p != pEnd:
			stOctet = ord(self.encodedFile[p])
			p += 1
			# print('stOctet',stOctet)
			if stOctet < 192:
				length = stOctet
			elif stOctet < 255:
				ndOctet = ord(self.encodedFile[p])
				p += 1
				length = (stOctet - 192 << 8) + ndOctet + 192
			else:
				length = Util.toint(self.encodedFile[p: p + 4])
				p += 4
			subpacketType = ord(self.encodedFile[p])
			subpacketData = self.encodedFile[p+1: p+length]
			p += length
			# subpacketData = binascii.hexlify(subpacketData)
			dataSet[subpacketType] = subpacketData
		return dataSet

	def makeSubPacket(self, dataSet):
		out = ''
		for subpacketType in dataSet:
			length = self.len2NewFormat(1 + len(dataSet[subpacketType]))#precissa de modificacoes
			out += length + chr(subpacketType) + dataSet[subpacketType]
		return out

	def read_SignaturePacket(self, p, pEnd):
		# 5.2.  Signature Packet (Tag 2)
		pv = p
		version = ord(self.encodedFile[p])
		p += 1
		# print('version:',version)
		if version == 3:
			print '''5.2.2.  Version 3 Signature Packet Format'''
			exit(1)
		elif version == 4:
			signatureType = ord(self.encodedFile[p])
			# print('signatureType:',signatureType)
			p += 1

			publicKeyAlgo = ord(self.encodedFile[p])
			# print('publicKeyAlgo:',publicKeyAlgo)
			p += 1

			hashAlgoId = ord(self.encodedFile[p])
			# print('hashAlgoId:',hashAlgoId)
			p += 1
			hashAlgo = Util.hashAlgo(hashAlgoId)

			hashedSubpacketLen = Util.toint(self.encodedFile[p: p+2])
			# print('hashedSubpacketLen:',hashedSubpacketLen)
			p += 2

			hashedSubpacket = self.leSubPacket(p, p+hashedSubpacketLen)
			p += hashedSubpacketLen
			# print('hashedSubpacket:', hashedSubpacket)

			ph = p

			unhashedSubpacketLen = Util.toint(self.encodedFile[p: p+2])
			# print('unhashedSubpacketLen:',unhashedSubpacketLen)
			p += 2

			unhashedSubpacket = self.leSubPacket(p, p+unhashedSubpacketLen)
			p += unhashedSubpacketLen
			# print('unhashedSubpacket:', unhashedSubpacket)

			signedHashValue = self.encodedFile[p: p+2]
			# print('signedHashValue:', binascii.hexlify(signedHashValue))
			p += 2

			while p != pEnd:
				p, mm = Util.leMPI(self.encodedFile, p)

				#9.1.  Public-Key Algorithms
				if publicKeyAlgo == 1 or publicKeyAlgo == 2 or publicKeyAlgo == 3:
					#rsa
					if signatureType == 0x18:
						sig = self.asymKey.packet
						sig += self.asymSubKey.packet
						
						asymKeys = [self.asymKey]
					elif signatureType == 0x13:
						sig = self.asymKey.packet
						sig += binascii.unhexlify('b4' + '{0:0{1}x}'.format(len(self.asymKey.userId), 8))
						sig += self.asymKey.userId

						asymKeys = [self.asymKey]
					elif signatureType == 0x00:
						sig = self.encodedFile[self.paketStart:self.paketEnd]

						# print('len(self.asymmetricKeys)', len(self.asymmetricKeys))
						asymKeys = []
						for asymKey in self.allKeys():
							# print 'asymKey.keyId', binascii.hexlify(asymKey.keyId)
							if asymKey.keyId == self.keyId:
								asymKeys.append(asymKey)
					elif signatureType == 0x10:
						print '''Not Implemented yet signatureType''' , hex(signatureType)
						return p
					else:
						print '''Not Implemented yet signatureType''' , hex(signatureType)
						exit(1)

					sig += self.encodedFile[pv:ph]
					sig += binascii.unhexlify("04ff")
					sig += binascii.unhexlify('{0:0{1}x}'.format(ph-pv, 8))

					hld = hashAlgo(sig).digest()
					if hld[:2] != signedHashValue:
						raise OpenPGPIncorrectException('left 16 bits of signed hash', hashAlgo.__name__, hld[:2], signedHashValue)
					if len(asymKeys) == 0:
						raise OpenPGPKeyIdException(self.keyId, len(self.asymmetricKeys))
					elif len(asymKeys) > 1:
						print '>>> has multiples possibilities of key for this signature <<<',len(self.asymmetricKeys)
						exit(1)
					else:
						#Util.display('asymKeys[0].unsignRSA(mm)',asymKeys[0].unsignRSA(mm))
						mm2 = asymKeys[0].unsignRSA(mm)[-len(hld):]
						# print 'mml2', binascii.hexlify(mm2)
						if hld != mm2:
							raise OpenPGPIncorrectException('signed hash', hashAlgo.__name__, hld, mm2)
						else:
							print hex(signatureType), 'validado com sucesso:', binascii.hexlify(mm2)
				elif publicKeyAlgo == 16:
					#Elgamal
					print '''5.5.2.  Public-Key Packet Formats Elgamal public key'''
					exit(1)
				elif publicKeyAlgo == 17:
					#DSA
					print '''>>> 5.5.2.  Public-Key Packet Formats DSA public key'''
					# exit(1)
				else:
					print('publicKeyAlgo',publicKeyAlgo,'not suported')
					exit(1)
		else:
			print '>>> Signature Packet version must be 3 or 4 <<<'
			exit(1)
		return p

	def write_SignaturePacket(self, signatureType, hashAlgoId, passphrase):
		# 5.2.  Signature Packet (Tag 2)
		version = chr(4)
		hashedSubpacket = self.makeSubPacket({33: chr(4) + self.asymKey.fingerPrint, 2: Util.TIMENOW()})#'Z\xb9\x9c?'#Util.int2str256(int(time.time()), 4)
		hashedSubpacketLen = Util.int2str256(len(hashedSubpacket), 2)

		fistPart = (version
			+ chr(signatureType)
			+ chr(self.asymKey.publicKeyAlgo)
			+ chr(hashAlgoId)
			+ hashedSubpacketLen
			+ hashedSubpacket)

		unhashedSubpacket = self.makeSubPacket({16: self.asymKey.keyId})
		unhashedSubpacketLen = Util.int2str256(len(unhashedSubpacket), 2)

		if signatureType == 0x00:
			sig = self.literalData
		elif signatureType == 0x13:
			sig = self.asymKey.packet
			sig += binascii.unhexlify('b4' + '{0:0{1}x}'.format(len(self.asymKey.userId), 8))
			sig += self.asymKey.userId
		elif signatureType == 0x18:
			sig = self.asymKey.packet
			sig += self.asymSubKey.packet
		else:
			print '''Not Implemented(write) yet signatureType''' , hex(signatureType)
			exit(1)

		sig += fistPart
		sig += binascii.unhexlify("04ff")
		sig += binascii.unhexlify('{0:0{1}x}'.format(len(fistPart), 8))
		hld = Util.hashAlgo(hashAlgoId)(sig).digest()

		signedHashValue = hld[:2]

		mm2 = Util.EMSA_PKCS1_v1_5(hld, hashAlgoId, self.asymKey.messegeLen)
		mm = self.asymKey.signRSA(mm2, passphrase)

		return (fistPart
			+ unhashedSubpacketLen
			+ unhashedSubpacket
			+ signedHashValue
			+ Util.toMPI(mm))

	def read_CompressedDataPacket(self, p, pEnd):
		# 5.6.  Compressed Data Packet (Tag 8)
		compressAlgo = ord(self.encodedFile[p])
		p += 1
		# 9.3.  Compression Algorithms
		if compressAlgo == 1:
			#zip
			decompressedFile = zlib.decompress(self.encodedFile[p: pEnd], -15)
			print 'new myOpenPGP zip decompressedFile'
			myOpenPGP().setAsymmetricKeys(self.asymmetricKeys).readFile(decompressedFile)
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

	def read_One_Pass_Signature_Packets(self, p):
		# 5.4.  One-Pass Signature Packets (Tag 4)
		version = ord(self.encodedFile[p])
		p += 1
		if version == 3:
			signatureType = ord(self.encodedFile[p])
			#5.2.1.  Signature Types
			p += 1

			hashAlgoId = ord(self.encodedFile[p])
			p += 1

			publicKeyAlgo = ord(self.encodedFile[p])
			p += 1

			self.keyId = self.encodedFile[p: p + 8]
			print 'keyId', binascii.hexlify(self.keyId)
			p += 8

			flagLastOnePass = ord(self.encodedFile[p])
			p += 1

			if flagLastOnePass == 0:
				print ''' 5.4.  One-Pass Signature Packets (Tag 4) '''
				exit(1)
			# else:
		else:
			print '>>> One-Pass Signature Packets version must be 3 <<<'
			exit(1)
		return p

	def write_One_Pass_Signature_Packets(self, signatureType, hashAlgoId):
		# 5.4.  One-Pass Signature Packets (Tag 4)
		version = chr(3)
		flagLastOnePass = chr(1)

		return (version
			+ chr(signatureType)
			+ chr(hashAlgoId)
			+ chr(self.asymKey.publicKeyAlgo)
			+ self.asymKey.keyId
			+ flagLastOnePass)

	def readTag(self, tag, p, length):
		print('tag:', tag, length)
		if tag == 5 or tag == 7 or tag == 6 or tag == 14:
			keyRSA = RSAOpenPGP().read(self.encodedFile[p:p+length])
			Util.display('fingerPrint', keyRSA.fingerPrint)
			if tag == 5 or tag == 6:
				for asymKey in self.asymmetricKeys:
					if asymKey.fingerPrint == keyRSA.fingerPrint and asymKey.nRSA == keyRSA.nRSA:
						if not asymKey.hasSecretData and keyRSA.hasSecretData:
							asymKey.insertSecretData(keyRSA)
						self.asymKey = asymKey
						break
				else:
					self.asymmetricKeys.append(keyRSA)
					self.asymKey = keyRSA
			else:
				for asymSubKey in self.asymKey.subKeys:
					if asymSubKey.fingerPrint == keyRSA.fingerPrint and asymSubKey.nRSA == keyRSA.nRSA:
						if not asymSubKey.hasSecretData and keyRSA.hasSecretData:
							asymSubKey.insertSecretData(keyRSA)
						self.asymSubKey = asymSubKey
						break
				else:
					self.asymKey.subKeys.append(keyRSA)
					self.asymSubKey = keyRSA
			return p + length
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
		elif tag == 4:
			return self.read_One_Pass_Signature_Packets(p)
		else:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!tag readTag', tag)
			print('!length', length)
			exit(1)

	def writeTag(self, tagInfo):
		tag = tagInfo[0]
		if tag == 1:
			return self.write_Public_Key_Encrypted_Session_Key_Packets()
		elif tag == 18:
			return self.write_SymEncryptedIntegrityProtectedDataPacket(tagInfo[1])
		elif tag == 11:
			return self.write_LiteralDataPacket(tagInfo[1])
		elif tag == 19:
			return self.write_ModificationDetectionCodePacket()
		elif tag == 4:
			return self.write_One_Pass_Signature_Packets(tagInfo[1], tagInfo[2])
		elif tag == 2:
			return self.write_SignaturePacket(tagInfo[1], tagInfo[2], tagInfo[3])
		elif tag == 5:
			return self.write_secretKeyPaket(tagInfo[1])
		elif tag == 7:
			return self.write_secretKeyPaket(tagInfo[1], tagInfo[2])
		elif tag == 6:
			return self.write_publicKeyPaket(tagInfo[1])
		elif tag == 14:
			return self.write_publicKeyPaket(tagInfo[1], tagInfo[2])
		elif tag == 13:
			return self.write_UserIDPacket()
		else:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!tag writeTag', tag)
			exit(1)
			
	def crc24(self, octets):
		#6.1.  An Implementation of the CRC-24 in "C"
		crc = CRC24_INIT = 0xB704CEL
		CRC24_POLY = 0x1864CFBL
		for x in octets:
			crc ^= ord(x) << 16
			for i in xrange(8):
				crc <<= 1
				if (crc & 0x1000000):
					crc ^= CRC24_POLY
		return crc

	def encodeAsc(self, title = 'MESSAGE'):
		crcFile = self.crc24(self.encodedFile)
		base64File = base64.b64encode(self.encodedFile)
		self.encodedFile = "-----BEGIN PGP " + title + "-----\n\n"
		p = 0
		while p < len(base64File):
			self.encodedFile += base64File[p: p+64] + '\n'
			p += 64
		self.encodedFile += '=' + base64.b64encode(Util.int2str256(crcFile, 3)) + '\n'
		self.encodedFile += '-----END PGP ' + title + '-----\n'
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
			print '> crc24 calculeded',base64.b64encode(Util.int2str256(crcFile, 3))
			exit(1)
		return self

	def saveFile(self, fileName, armor = None, needValidadion = False):
		if armor:
			self.encodeAsc(armor)
			fileName += '.asc'
		else:
			fileName += '.gpg'
		if fileName == '.asc' or fileName == '.gpg':
			print self.encodedFile
		else:
			if needValidadion and os.path.isfile(fileName):
				confirm = raw_input("The " + fileName + " file already exists. Do you want to overwrite it?").lower()
				if confirm[0] != 'y':
					print 'File was not saved'
					return self
			open(fileName, "wb").write(self.encodedFile)
		return self

	def savePrivateKey(self, userId, fileName, passphrase, armor = False, needValidadion = False):
		tags = []
		for i, asymKey in enumerate(self.asymmetricKeys):
			if userId.lower() not in asymKey.userId.lower():
				continue
			if not asymKey.hasSecretData:
				continue
			tags.append([5, i])
			tags.append([13])
			tags.append([2, 0x13, 8, passphrase])
			for j in range(len(asymKey.subKeys)):
				tags.append([7, i, j])
				tags.append([2, 0x18, 8, passphrase])

		if tags != []:
			self.writeFile(tags)
		else:
			print 'There is no Secret Keys for user', userId
			return self
		if armor:
			self.saveFile(fileName, 'PRIVATE KEY BLOCK', needValidadion)
		else:
			self.saveFile(fileName, None, needValidadion)
		return self

	def savePublicKey(self, userId, fileName, passphrase, armor = False, needValidadion = False):
		tags = []
		for i, asymKey in enumerate(self.asymmetricKeys):
			if userId.lower() not in asymKey.userId.lower():
				continue
			tags.append([6, i])
			tags.append([13])
			tags.append([2, 0x13, 8, passphrase])
			for j in range(len(asymKey.subKeys)):
				tags.append([14, i, j])
				tags.append([2, 0x18, 8, passphrase])

		if tags != []:
			self.writeFile(tags)
		else:
			print 'There is no Public Keys for user', userId
			return self
		if armor:
			self.saveFile(fileName, 'PUBLIC KEY BLOCK', needValidadion)
		else:
			self.saveFile(fileName, None, needValidadion)
		return self

	def signFile(self, signFile, userId, fileName, passphrase, armor = False, needValidadion = False):
		tags = []
		for i, asymKey in enumerate(self.asymmetricKeys):
			if userId.lower() not in asymKey.userId.lower():
				continue
			if not asymKey.hasSecretData:
				continue
			self.asymKey = asymKey
			self.asymSubKey = asymKey.subKeys[0]
			signatureType = 0x00
			hashAlgoId = 8
			tags = [[4, signatureType, hashAlgoId], [11, signFile], [2, signatureType, hashAlgoId, passphrase]]

		if tags != []:
			self.writeFile(tags)
		else:
			print 'There is no Secret Keys for user', userId
			return self
		if armor:
			self.saveFile(fileName, 'MESSAGE', needValidadion)
		else:
			self.saveFile(fileName, None, needValidadion)
		return self

	def encrypt(self, encryptFile, userId, fileName, armor = False, needValidadion = False):
		tags = []
		for i, asymKey in enumerate(self.asymmetricKeys):
			if userId.lower() not in asymKey.userId.lower():
				continue
			self.asymKey = asymKey.subKeys[0]
			tags = [[1], [18, [[11, encryptFile], [19]]]]

		if tags != []:
			self.writeFile(tags)
		else:
			print 'There is no Public Keys for user', userId
			return self
		if armor:
			self.saveFile(fileName, 'MESSAGE', needValidadion)
		else:
			self.saveFile(fileName, None, needValidadion)
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

	def writeFile(self, tags, extraParam = None):
		self.encodedFile = ''
		self.extraParam = extraParam

		for tag in tags:
			self.encodedFile += chr(192 + tag[0])#chr((1<<7) + (1<<6) + tag)
			packet = self.writeTag(tag)
			self.encodedFile += self.len2NewFormat(len(packet)) + packet
		return self

	def readFile(self, encodedFile, extraParam = None):
		print '==readFile'
		self.encodedFile = encodedFile
		self.extraParam = extraParam
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
				print '>>>>>>>>>>>>>>>>>>>> the beggin of block must be 1 <<<<<<<<<<<<<<<<<<<<'
				print binascii.hexlify(self.encodedFile[:p-1])
				print binascii.hexlify(self.encodedFile[p-1:])
				exit(1)
			newFormat = pTag & 64#1<<6
			if newFormat:
				tag = pTag & 63#(1<<6)-1
				stOctet = ord(self.encodedFile[p])
				p += 1
				# print('stOctet',stOctet)
				if stOctet < 192:
					length = stOctet
				elif stOctet < 224:
					ndOctet = ord(self.encodedFile[p])
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
			#print '??? ',p, length, p+length, len(self.encodedFile)
			p = self.readTag(tag, p, length)

		# print()
		# print(p)
		# print(len(self.encodedFile))
		if p == len(self.encodedFile):
			print '==', True
		else:
			print '==', False
			exit(1)

		# self.encodeAsc()
		# print self.encodedFile
		return self
