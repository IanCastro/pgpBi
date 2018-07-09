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

passphase = "this is a pass"

praTestar = True
if praTestar:
	myOpenPGP().readFile(ExampleFile)
	myOpenPGP().readFile(publicKeyQWFile).readFile(File2File)
	myOpenPGP().readFile(secretKeyFile).readFile(ml2File)
	myOpenPGP().readFile(publicKeyQWFile).encrypt("file.txt", "", "file.txt", True)
	FileFile = open("file.txt.asc", "rb").read()
	myOpenPGP().readFile(secretKeyFile).signFile("file.txt", "", "mySign", passphase, True)
	mySignFile = open("mySign.asc", "rb").read()
	myOpenPGP().readFile(publicKeyQWFile).readFile(mySignFile)
	myOpenPGP().readFile(rnKeyFile).readFile(compressZipFile)
	myOpenPGP().readFile(secretKeyFile).savePrivateKey("", "genSecrKey", passphase)
	genSecrKeyFile = open("genSecrKey.gpg", "rb").read()
	myOpenPGP().readFile(genSecrKeyFile).readFile(mTxtFile)
	myOpenPGP().readFile(secretKeyFile).savePrivateKey("", "genSecrKey", passphase, True)
	genSecrKeyAscFile = open("genSecrKey.asc", "rb").read()
	myOpenPGP().readFile(genSecrKeyAscFile).readFile(FileFile)
	myOpenPGP().generateKeyRSA("myUser <my@user.com>", 'this is a pass').savePrivateKey("user", "mySecrKey", passphase, True).savePublicKey("user", "myPublKey", passphase).signFile("file2.txt", "my@user.com", "euSign", passphase)
	myPublKeyAscFile = open("myPublKey.gpg", "rb").read()
	myOpenPGP().readFile(myPublKeyAscFile).readFile(open("euSign.gpg", "rb").read()).encrypt("file.txt", "my@user.com", "euEncript", True)
	mySecrKeyAscFile = open("mySecrKey.asc", "rb").read()
	myOpenPGP().readFile(mySecrKeyAscFile).readFile(open("euEncript.asc", "rb").read())
	myOpenPGP().readFile(publicKeyQWFile).readFile(publicKeyQWFile).readFile(File2File)
	myOpenPGP().readFile(publicKeyQWFile).readFile(secretKeyFile).readFile(ml2File).readFile(File2File)
	myOpenPGP().generateKeyRSA("uu <u@mail.com>", 'pass').savePrivateKey("uu", "changeSKey", "pass").readFile(open("changeSKey.gpg", "rb").read()).readFile(open("changeSKey.gpg", "rb").read()).generateKeyRSA("nn <n@mail.com>", 'pp').readFile(open("changeSKey.gpg", "rb").read()).savePrivateKey("nn", "changeSKey", "pp").readFile(open("changeSKey.gpg", "rb").read())
	print "== OK"
else:
	myOpenPGP().start()
