# pgpBi
Implementação do OpenPGP

Usage: In a terminal enter the command "python myOpenPGP.py"

Commands:

(GenerateKey | -g) [Cryptosystem [UserName [e-mail [passphase]]]]

(ReadFile | -r) [FileName]

(Encrypt | -e) FileName [User] [Options...]

(Sign | -s) FileName [User] [Options...]

(Export-Key | -pk) [User] [Options...]

(Export-Secret-Key | -sk) [User] [Options...]

(Help | -h) [command]

Exit


Argumentos:

Cryptosystem: Cryptosystem used to generate the key, only "rsa" avaliable

UserName: name of the owner of the key

e-mail: e-mail of the owner of the key

passphase: sequence of words to protect from other people using the key

FileName: File to be processed

User: UserName or e-mail

Options: one or more of these arguments

  (--armor | -a): Convet the output to Base64
  
  (--ignore | -i): Do not ask if you want replace the output file(always replace)
  
  (--output | -o) OutputFile: Set OutputFile as name to save the generated packet
  
  (--compress | -c) compression: The compression to be used, only "zip" available
  
  (--pass | -p) passphrase: Passphrase to use the secret key


Obs: passphrase and user containing spaces need to be surrounded by \"(quotation marks)

