import binascii
from datetime import datetime
import hashlib
from Crypto.Cipher import AES


class openPGP:
	secretKey_gpg = '9503c6045a1c710b0108009c2c845323709a36b31327dae1a5a8ab49450ce6d37169aa9975c42a500b8a581c4412530bd6ab8ab04f84b7948e1ded21b85ff1252750c0b7b017a99b439df76ffbb42ff143609ab4eaae2b0cb329a731da12934b106f51c37cc558f2d3284b13a36015ff770e490d40adcd2c735cbf8a8dd57bbe0ba08a9996f7532376391f16935ffc0291aa69ab9e39d68d622e57f480a79c14c409a31cc3ab26b2f85cd86b7fdf5f192ad253527b2a9013d97a046131d4cb8ef83bcdde77e1ffb84e023f53491e6442124283db43d3ec5403a337365d9b3f9a0d603173a480d2e8138b9449775d8a8cf264bfe99afa7a0c34f54b686af0387654d9320f8ff9ffffe0fbd30011010001fe070302c7cbbb63b008a42dee0d7627eba029ae7cff91848ca023a87f60557a2390b1e0df7289e42e2c040cd8bbf4de75ea991bb633ecceb2c8897afa2e9d1936f903d7a58d414bdb0d7ef242f6e2ea9e9a7d85c4d80fd479c32c4f8e879a8497f410cd7da96bf7475c613a25d28bad09bf21e58104b08f629842bdca22d8a9334744565efeb54e10db120ef3d5d61a17dcca70ca20bb4a0a1a0d34211d3c8153d147c212049b2e1fe9c9a5fc7e20d909b625979165054363cc1d3581202f7ccafa542ccf113f2a338c83bb394c10a37fd45b6bb204af07afffa8e5859c12fdf0dbec30c895006111f3d74e5cdbb0a2ae08bec687109a165a6b373862065367d9bb868277b44f7ec2b1c35a7f713ee936a9fa60a2a19ad625896029344469f053225865ad0ee9413ed091067b4aa4318c771659841ce68302bddd0f2549b3f8947182bedb666452a4d56d7a8d317d85cbe1647761f130f8151a3bd94ab10f3cf5a828b893589188bec4125446db2c9948e77b4c1c5cb1b2d6b86b08d1874a20317224dda64ac90b671052d3ea7106e9071b780a92b9c13e39851c0bf69f9c126c5f0bf95eb784b3dd522d22affe74655587e938a27a1d909efae2706815140f06af300d9160dfe3badf184d8b6865a9c091405b7e78acb51cc5b196c7632cbb2a9e570a28216466a8e54b767698baadf87230c8b514c16151b7d557c75bcd6d8048b0287428578d9fc91b0ebfc8653276cf1232a3b4e0ce1d758ad5436be7dc9654b93fa5efe0aee32273513c043a6ec792817a0aace151d9b7890d4c3c7963bba8905d5bf7b79392ab06d8d9194bb6adcc3acc0c74a9325e6fb5949b68e789ed60042f20fb4e100affe20b917f35dc7c524fdae081d3c2379ef5ef6c2884b5d7bee2512e91ad5d4e0f6fe6860e49d212daae480896c3ad7ba204e3b820a3a7f60aa456b6058e7bb59b35e03e7eb1974d505cac51a0dbb916b40f7177657274203c7140772e636f6d3e89015204130108003c1621048a2c408d380867f91acda20b17cdc12bc692c08405025a1c710b021b03050903c26700050b09080702061508090a0b02021600021e01021780000a091017cdc12bc692c084f0cd07ff6fe5a70eaf59af324441c7dbb71afe3a1b8a84124e9eed78d8099cb48a427ae1071b0121ac96e221a50798975a833187c84c5362b110340b80d21d71256146131d09d8f553f11c101d884dfd05553fe161567db97e882553a3852421a8adf55cd8eaf0d7a547a1a774d718637da772d9fa141ebc1bbaae52efed6292cf525368586c477cfb05766d7abee17527b3086a2f9bf235dc46fed6d62c867bee01572105e7a0d51f68aff3ad218a37228528e65586c6de35f66d0c7e57be14cf11814c2d8db226f3972b452a0ee576b06c5fef390e0f3f7a5a580ca38cd594f70df5090dbdd6a5d7844c722c452d4c7db9e7f67f44f37adcc3cec4270f5341a3996ba59d03c6045a1c710b0108009fed7a4e822a2c4a44618c1aef09ec36ce64565663ea12d4f581c599378dfbf75e2401ade55b277be405b1a55a348431c3c7b11289a47a59cc0eb8180b0a6e09c68fb3b65e8c14dd419f8b35d1af23bb43fa12d0a76416c324c1151c17c68c5d8e66dc735367394808167c0b6fa2de3af25117d1cc069029d55fb266f4dcbcf27726dad9f323b7a79e8bdb874f9320074202d4d4209366bb6f9afea0bb9fa9f0d2f8c606e96cb71e8746bdd651b78754c95b96de0708aa87b121d5c5ab155591285ce95f9145b4d17496dbd63a9f50e3f7d8a4a0d9792686cdcaeb0aed5e3ce7232eb3a13527744ef107ee675fdca8a4b1556f3fa3bdfb4e0edd77c0fe46e16d0011010001fe0703029f1078b78d5d6560ee0802df5d1fb6a9fd1f2b9cb0a65bc776540f583a1b6496c682ef5aa3e6339cf82470ff729845f80ce985500aedcf5719af469254d8862886f655347375c7150957ce75fbdf53a5bab59d802477260761ad89da9a91ee753cb065a31399f475d411dcf25f53d86456457ff08577b6079fa2f7d2aba42149bedd13a20b74e8c4de14f18e8e1f7666231643d7117a92f629d622ebf6d2046197ece88175eefc913e6528995d75af1f86b7c3d86871e500604881516534d415de1c2feff7db896eb5022fda6e77ffe30f7aca26b37527f5aa4f8063ba8f614ae4f53a4bbee3d01ca9c5779e15508dd0261d1b40a6a4c17f1c09cf0116b43cc617ddbe2970b7c92548bd93d16fa10a16a63dae28b21fef3ae28231d6e17676100eae11a059c776409720142a1b785bff0679533d299f5365e45937494180a675e71e5cc13b58ec7f5f557c581ac0281b27396335a901f21eac6325a8bf6edf726d90201952e2dbab1e91e8d458bdd469cbe7672fbe6f2ffff18faa5027c1785ec86993a03b3c7899c72782c3522515c9388c6081cc5c324971d9ced4a8d07c71bac40368e052c75021562aebb8f66f6ab5c0e6f4704e4d7ae5c463c6acbfcf46f46c1116bebf4e0f1c859589e1e715dacd1cd142ab0359084165ab73fb0c52781d4eea53407e269db9c167d2bc58d88dc04872644d1e363c8d91a8e6165e2ec5383c948135ed02c7a9b92282d4a6ff13102468c5916b834c75c0d83251ad8e5cba69302b183a471582a35e81cc3811376cc9f85e7ef6f16a26e0767e6bdd2daf53ce008c752045a1604e6219784aaa2ada7821b69a586388a5e26c66bd97c5c0b70eb1b7ea9c5e2a67ceaf30906853f191d80e10e6b353906d21ba141650f6d1526f0beb13849e075890c0883492a494a7d5aa3e779c904baf0136c07fd2acda41dc5cd7b133b70caaeca8d328d575398e9da693f289013c0418010800261621048a2c408d380867f91acda20b17cdc12bc692c08405025a1c710b021b0c050903c26700000a091017cdc12bc692c0843b3807ff5348f7b915f9b43269bf098a6132cd5486e470a7c78ee44f5f02924ed7c692418c86088f69ff19644fbe83e4bf4caeb50c6a6eb147b692d4405cbd6c51e39c3df53a9bc459e442410bea837007bb4323380ff351f2e787c40284c3755a1b961783bda6c64844f08e14132190820c8f2d4edb3ab7e1c99a506b395851fa49801f090a28bb11a0d2c20599e71e028776cd837b3dd8f758939cc48cdc62a5b167e25f58c0b71e36c6e406719419864c2038970f96cff03196cfd3fc8049d5d70d7d6a64fbb270d699a17246c6631ec62f6935a3a35aabfa8fc08a7ddf3538bf22030369a63722637ba7aac8c1ea91af58ec9a400f583c196992a7dc668ebbd5739d'
	secretKey_gpg = binascii.unhexlify(secretKey_gpg)



	def toint(self, str256):
		return reduce(lambda x,y:x*256+ord(y), str256, 0)

	def leMPI(self, p):
		length = (self.toint(self.secretKey_gpg[p: p + 2]) + 7) / 8
		p += 2
		mpi = self.secretKey_gpg[p: p + length]
		p += length
		return (p, mpi)

	def leMPId(self, p, data):
		length = (self.toint(data[p: p + 2]) + 7) / 8
		p += 2
		mpi = data[p: p + length]
		p += length
		return (p, mpi)
		
	def blockSize(self, algo):
		if algo == 7:
			return 16
		else:
			print'''#9.2.  Symmetric-Key Algorithms'''
			exit(1)

	def makeKey(self, salt, coded, bs, passphrase):
		#3.7.1.3.  Iterated and Salted S2K
		count = (16 + (coded & 15)) << ((coded >> 4) + 6);
		print'count',count
		comb = salt+passphrase
		print'comb',binascii.hexlify(comb)
		while len(comb) < count:
			comb += comb
		comb = comb[:count]

		hd = hashlib.sha1(comb).digest()
		return hd[:bs]

	def printgpg(self, p, t):
		print(binascii.hexlify(self.secretKey_gpg[p:p+t]))

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
		if hashlib.sha1(data[:p]).digest() == data[p:]:
			print'pass'
			print'dRSA',binascii.hexlify(dRSA)
			print'pRSA',binascii.hexlify(pRSA)
			print'qRSA',binascii.hexlify(qRSA)
			print'uRSA',binascii.hexlify(uRSA)
		else:
			print'not pass'

		
		#print'sha1',hashlib.sha1(data[:p]).hexdigest()
		#print'sha1',binascii.hexlify(data[p:])


	def secretKeyPaket(self, p, pEnd):
		#5.5.3.  Secret-Key Packet Formats
		p = self.publicKeyPaket(p)
		s2kConventions = ord(self.secretKey_gpg[p])
		p += 1
		if s2kConventions == 254 or s2kConventions == 255:
			symEncAlgo = ord(self.secretKey_gpg[p])
			self.printgpg(p, 1)
			p += 1
			#9.2.  Symmetric-Key Algorithms
			s2k = ord(self.secretKey_gpg[p])
			self.printgpg(p, 1)
			p += 1
			#3.7.1.  String-to-Key (S2K) Specifier Types
			hashAlgo = ord(self.secretKey_gpg[p])
			self.printgpg(p, 1)
			p += 1
			salt = self.secretKey_gpg[p: p + 8]
			self.printgpg(p, 8)
			p += 8
			coded = ord(self.secretKey_gpg[p])
			self.printgpg(p, 1)
			p += 1
			bs = self.blockSize(symEncAlgo)
			IV = self.secretKey_gpg[p: p + bs]
			self.printgpg(p, bs)
			p += bs
			encrData = self.secretKey_gpg[p: pEnd]
			p = pEnd

			self.leSecretData('this is a pass', symEncAlgo, salt, coded, encrData, IV)
			# key = self.makeKey(salt, coded, bs, 'this is a pass')
			# encrData = encrData+chr(0)*4
			# data = AES.new(key, AES.MODE_CFB, IV, segment_size = 128).decrypt(encrData)[:-4]
			# print'data',binascii.hexlify(data)

			# exit(0)
		return pEnd



			
	def publicKeyPaket(self, p):
		#5.5.2.  Public-Key Packet Formats
		version = ord(self.secretKey_gpg[p])
		p += 1
		print('v',version)
		if version == 3:
			print'''5.5.2.  Public-Key Packet Formats //version 3'''
		elif version == 4:
			dateCreated = datetime.fromtimestamp(self.toint(self.secretKey_gpg[p: p+4]))
			p += 4
			print(dateCreated.strftime('%H:%M:%S %d/%m/%Y'))
			algorithm = ord(self.secretKey_gpg[p])
			p += 1
			#9.1.  Public-Key Algorithms
			if algorithm == 1 or algorithm == 2 or algorithm == 3:
				#rsa
				p, nRSA = self.leMPI(p)
				print'nRSA',binascii.hexlify(nRSA)
				p, eRSA = self.leMPI(p)
				#print(eRSA, mpi)
			elif algorithm == 16:
				print'''5.5.2.  Public-Key Packet Formats Elgamal public key'''
				#Elgamal
			elif algorithm == 17:
				print'''5.5.2.  Public-Key Packet Formats DSA public key'''
				#DSA
			else:
				print('algorithm',algorithm,'not suported')
				exit(1)

		else:
			print 'Public key paket version must be 3 or 4'
			exit(1)
		return p

	def leTag(self, tag, p, length):
		if(tag == 5 or tag == 7):
			return self.secretKeyPaket(p, p+length)
		elif tag == 6 or tag == 14:
			return self.publicKeyPaket(p)
		elif tag == 1:
			return self.Public_Key_Encrypted_Session_Key_Packets(p)
		else:
			return p + length

	def ff(self):
		p = 0
		while(p < len(self.secretKey_gpg)):
			print(p,len(self.secretKey_gpg))
			pTag = ord(self.secretKey_gpg[p])
			p += 1
			print('pTag',pTag)
			one = pTag & 128#1<<7
			if not one:
				print 'the beggin of block must be 1'
				exit(1)
			newFormat = pTag & 64#1<<6
			if newFormat:
				tag = pTag & 63#(1<<6)-1
				stOctet = ord(self.secretKey_gpg[p]);
				p += 1
				if stOctet < 192:
					length = stOctet
				elif stOctet < 224:
					ndOctet = ord(self.secretKey_gpg[p]);
					p += 1
					length = (stOctet - 192 << 8) + ndOctet + 192
				elif stOctet == 255:
					#length = reduce(lambda x,y:x*256+ord(y), self.secretKey_gpg[p: p + 4], 0)
					length = self.toint(self.secretKey_gpg[p: p + 4])
					p += 4
				else:
					print'''4.2.2.4.  Partial Body Lengths'''
			else:
				tag = (pTag & 63) >> 2#(tag & (1<<6)-1) >> 2
				lenType = pTag & 3#(1<<2)-1
				#print('lenType',lenType)
				if lenType < 3:
					#length = reduce(lambda x,y:x*256+ord(y), self.secretKey_gpg[p: p + (1<<lenType)], 0)
					length = self.toint(self.secretKey_gpg[p: p + (1<<lenType)])
					p += (1<<lenType)
				else:
					print'''4.2.1.  Old Format Packet Lengths// 3 - The packet is of indeterminate length'''


			print('one',one)
			print('newFormat',newFormat)
			print('tag',tag)
			print('length',length)
			p = self.leTag(tag, p, length)

		print()
		print(p)
		print(len(self.secretKey_gpg))

ff = openPGP()
ff.ff()