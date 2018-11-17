import hashlib

import Util
from OpenPGPExceptions import *

class S2kOpenPGP:
	def read(self, data, p):
		#3.7.1.  String-to-Key (S2K) Specifier Types
		p0 = p
		self.version = ord(data[p])
		p += 1
		if self.version != 0 and self.version != 1 and self.version != 3:
			raise OpenPGPVersionException('S2kOpenPGP', self.version, [0, 1, 3])

		self.hashAlgo = ord(data[p])
		p += 1

		if self.version == 1 or self.version == 3:
			self.salt = data[p: p + 8]
			p += 8

		if self.version == 3:
			coded = ord(data[p])
			self.count = (16 + (coded & 15)) << ((coded >> 4) + 6)
			p += 1

		self.packet = data[p0: p]
		return p

	def generate(self):
		self.version = 3
		self.hashAlgo = 2
		self.salt = Util.randOctets(8)
		coded = 238#0xee
		self.count = 31457280#(16 + (coded & 15)) << ((coded >> 4) + 6)

		self.packet = (chr(self.version)
			+ chr(self.hashAlgo)
			+ self.salt
			+ chr(coded))
		return self

	def makeKey(self, bs, passphrase):
		if self.version != 3:
			raise OpenPGPException('Not Implemented yet makeKey S2K version: ' + hex(self.version))
		#3.7.1.3.  Iterated and Salted S2K
		comb = self.salt+passphrase
		while len(comb) < self.count:
			comb += comb
		comb = comb[:self.count]

		if self.hashAlgo == 1:
			#MD5
			raise OpenPGPException('Not Implemented s2k MD5')
		elif self.hashAlgo == 2:
			#SHA1
			hd = hashlib.sha1(comb).digest()
		elif self.hashAlgo == 3:
			#RIPE-MD/160
			raise OpenPGPException('Not Implemented s2k RIPE-MD/160')
		elif self.hashAlgo == 8:
			#SHA256
			raise OpenPGPException('Not Implemented s2k SHA256')
		elif self.hashAlgo == 9:
			#SHA384
			raise OpenPGPException('Not Implemented s2k SHA384')
		elif self.hashAlgo == 10:
			#SHA512
			raise OpenPGPException('Not Implemented s2k SHA512')
		elif self.hashAlgo == 11:
			#SHA224
			raise OpenPGPException('Not Implemented s2k SHA224')
		else:
			raise OpenPGPNotValidException('Hash Algorithms', self.hashAlgo, [1, 2, 3, 8, 9, 10, 11])

		if len(hd) < bs:
			print '''need multiples hashes to make key'''
			raise OpenPGPException('3.7.1. String-to-Key (S2K) Specifier Types')
		return hd[:bs]
