import binascii
import random

import Util
from myOpenPGP import myOpenPGP

#class MyException(Exception):
#    pass


localTest = True
if localTest:
	random.seed(0)
	Util.myRandInt = random.randint

secretKeyFile = open("secretKey.asc", "rb").read()
publicKeyQWFile = open("publicKeyQW.asc", "rb").read()
ml2File = open("ml2.txt.gpg", "rb").read()
FileFile = open("file.txt.asc", "rb").read()
File2File = open("file2.txt.asc", "rb").read()
mySignFile = open("mySign.asc", "rb").read()
compressZipFile = open("compressZip.gpg", "rb").read()
rnKeyFile = open("../rnKey.asc", "rb").read()


praTestar = True
if praTestar:
	myOpenPGP().readFile(publicKeyQWFile)
	myOpenPGP().readFile(rnKeyFile)
	myOpenPGP().readFile(compressZipFile)
	print binascii.hexlify(myOpenPGP().readFile(File2File).encodedFile)
	myOpenPGP().readFile(secretKeyFile)
	myOpenPGP().readFile(secretKeyFile).readFile(File2File)
	myOpenPGP().readFile(secretKeyFile).readFile(ml2File)
	print myOpenPGP().readFile(secretKeyFile).writeFile([[1], [18]]).encodeAsc().savefile("file.txt.asc").encodedFile
	myOpenPGP().readFile(secretKeyFile).readFile(FileFile)
	myOpenPGP().readFile(secretKeyFile).writeFile([[4], [11], [2, 0x00]]).encodeAsc().savefile("mySign.asc")
	myOpenPGP().readFile(secretKeyFile).readFile(mySignFile)
	myOpenPGP().readFile(rnKeyFile).readFile(compressZipFile)
else:
	myOpenPGP().readFile(secretKeyFile).writeFile([[5], [13], [2, 0x13], [7], [2, 0x18]])
