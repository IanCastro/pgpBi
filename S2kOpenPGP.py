import hashlib

class S2kOpenPGP:
	def read(self, data, p):
		self.packet = ""
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
			self.coded = ord(data[p])
			self.count = (16 + (self.coded & 15)) << ((self.coded >> 4) + 6)
			# self.printgpg(p, 1)
			p += 1
		return p

	def getPaket(self):
		if self.packet == "":
			self.packet += chr(self.version)
			self.packet += chr(self.hashAlgo)

			if self.version == 1 or self.version == 3:
				self.packet += self.salt

			if self.version == 3:
				self.packet += chr(self.coded)
		return self.packet

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
