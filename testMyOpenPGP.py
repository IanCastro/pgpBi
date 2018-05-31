import binascii
import random

import Util
from myOpenPGP import myOpenPGP

#class MyException(Exception):
#    pass


secretKeyFile = open("secretKey.asc", "rb").read()
publicKeyQWFile = open("publicKeyQW.asc", "rb").read()#open("qwPk.gpg", "rb").read()
ml2File = open("ml2.txt.gpg", "rb").read()
File2File = open("file2.txt.asc", "rb").read()
compressZipFile = open("compressZip.gpg", "rb").read()
rnKeyFile = open("rnKey.asc", "rb").read()
ExampleFile = open("Example.asc", "rb").read()
mTxtFile = open("m.txt.asc", "rb").read()


praTestar = True
if praTestar:
	myOpenPGP().readFile(ExampleFile)
	myOpenPGP().readFile(publicKeyQWFile).readFile(File2File)
	myOpenPGP().readFile(secretKeyFile).readFile(ml2File)
	print myOpenPGP().readFile(publicKeyQWFile).writeFile([[1], [18]]).savefile("file.txt", armor = 'MESSAGE').encodedFile
	FileFile = open("file.txt.asc", "rb").read()
	myOpenPGP().readFile(secretKeyFile).writeFile([[4], [11], [2, 0x00]]).savefile("mySign", armor = 'MESSAGE')
	mySignFile = open("mySign.asc", "rb").read()
	myOpenPGP().readFile(publicKeyQWFile).readFile(mySignFile)
	myOpenPGP().readFile(rnKeyFile).readFile(compressZipFile)
	myOpenPGP().readFile(secretKeyFile).writeFile([[5], [13], [2, 0x13], [7], [2, 0x18]]).savefile("genSecrKey")
	genSecrKeyFile = open("genSecrKey.gpg", "rb").read()
	myOpenPGP().readFile(genSecrKeyFile).readFile(mTxtFile)
	myOpenPGP().readFile(secretKeyFile).writeFile([[5], [13], [2, 0x13], [7], [2, 0x18]]).savefile("genSecrKey", armor = 'PRIVATE KEY BLOCK')
	genSecrKeyAscFile = open("genSecrKey.asc", "rb").read()
	myOpenPGP().readFile(genSecrKeyAscFile).readFile(FileFile)
else:
	# genSecrKeyFile = open("genSecrKey.asc", "rb").read()
	myOpenPGP().readFile(secretKeyFile).writeFile([[5], [13], [2, 0x13], [7], [2, 0x18]]).savefile("genSecrKey")
	genSecrKeyFile = open("genSecrKey.gpg", "rb").read()
	myOpenPGP().readFile(genSecrKeyFile)
