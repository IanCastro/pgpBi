import binascii
import random

import Util
from myOpenPGP import myOpenPGP


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
	print myOpenPGP().readFile(publicKeyQWFile).writeFile([[1], [18]]).saveFile("file.txt", armor = 'MESSAGE').encodedFile
	FileFile = open("file.txt.asc", "rb").read()
	myOpenPGP().readFile(secretKeyFile).writeFile([[4], [11], [2, 0x00]]).saveFile("mySign", armor = 'MESSAGE')
	mySignFile = open("mySign.asc", "rb").read()
	myOpenPGP().readFile(publicKeyQWFile).readFile(mySignFile)
	myOpenPGP().readFile(rnKeyFile).readFile(compressZipFile)
	myOpenPGP().readFile(secretKeyFile).writeFile([[5, -1], [13], [2, 0x13], [7, -1, 0], [2, 0x18]]).saveFile("genSecrKey")
	genSecrKeyFile = open("genSecrKey.gpg", "rb").read()
	myOpenPGP().readFile(genSecrKeyFile).readFile(mTxtFile)
	myOpenPGP().readFile(secretKeyFile).writeFile([[5, -1], [13], [2, 0x13], [7, -1, 0], [2, 0x18]]).saveFile("genSecrKey", armor = 'PRIVATE KEY BLOCK')
	genSecrKeyAscFile = open("genSecrKey.asc", "rb").read()
	myOpenPGP().readFile(genSecrKeyAscFile).readFile(FileFile)
	myOpenPGP().generateKeyRSA("myUser <my@user.com>", 'this is a pass').savePrivateKey("user", "mySecrKey", True)
	mySecrKeyAscFile = open("mySecrKey.asc", "rb").read()
	myOpenPGP().readFile(mySecrKeyAscFile)
	print "== OK"
else:
	myOpenPGP().generateKeyRSA("myUser <my@user.com>", 'this is a pass').savePrivateKey("user", "mySecrKey", True)
	myOpenPGP().readFile(open("mySecrKey.asc", "rb").read())
