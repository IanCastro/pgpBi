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
	print myOpenPGP().readFile(publicKeyQWFile).setAsymKey(0, 0).writeFile([[1], [18, [[11, "file.txt"], [19]]]]).saveFile("file.txt", armor = 'MESSAGE').encodedFile
	FileFile = open("file.txt.asc", "rb").read()
	myOpenPGP().readFile(secretKeyFile).setAsymKey(0).writeFile([[4, 0, 8], [11, "file.txt"], [2, 0x00, 8]]).saveFile("mySign", armor = 'MESSAGE')
	mySignFile = open("mySign.asc", "rb").read()
	myOpenPGP().readFile(publicKeyQWFile).readFile(mySignFile)
	myOpenPGP().readFile(rnKeyFile).readFile(compressZipFile)
	myOpenPGP().readFile(secretKeyFile).writeFile([[5, -1], [13], [2, 0x13, 8], [7, -1, 0], [2, 0x18, 8]]).saveFile("genSecrKey")
	genSecrKeyFile = open("genSecrKey.gpg", "rb").read()
	myOpenPGP().readFile(genSecrKeyFile).readFile(mTxtFile)
	myOpenPGP().readFile(secretKeyFile).writeFile([[5, -1], [13], [2, 0x13, 8], [7, -1, 0], [2, 0x18, 8]]).saveFile("genSecrKey", armor = 'PRIVATE KEY BLOCK')
	genSecrKeyAscFile = open("genSecrKey.asc", "rb").read()
	myOpenPGP().readFile(genSecrKeyAscFile).readFile(FileFile)
	myOpenPGP().generateKeyRSA("myUser <my@user.com>", 'this is a pass').savePrivateKey("user", "mySecrKey", True).savePublicKey("user", "myPublKey").signFile("file2.txt", "my@user.com", "euSign")
	myPublKeyAscFile = open("myPublKey.gpg", "rb").read()
	myOpenPGP().readFile(myPublKeyAscFile).readFile(open("euSign.gpg", "rb").read()).encrypt("file.txt", "my@user.com", "euEncript", True)
	mySecrKeyAscFile = open("mySecrKey.asc", "rb").read()
	myOpenPGP().readFile(mySecrKeyAscFile).readFile(open("euEncript.asc", "rb").read())
	print "== OK"
else:
	myOpenPGP().generateKeyRSA("myUser <my@user.com>", 'this is a pass').savePrivateKey("user", "mySecrKey", True).savePublicKey("user", "myPublKey").signFile("file2.txt", "my@user.com", "euSign")
	myPublKeyAscFile = open("myPublKey.gpg", "rb").read()
	myOpenPGP().readFile(myPublKeyAscFile).readFile(open("euSign.gpg", "rb").read()).encrypt("file.txt", "my@user.com", "euEncript", True)
	mySecrKeyAscFile = open("mySecrKey.asc", "rb").read()
	myOpenPGP().readFile(mySecrKeyAscFile).readFile(open("euEncript.asc", "rb").read())
