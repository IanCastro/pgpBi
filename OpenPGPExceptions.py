import binascii

class OpenPGPException(Exception):
	pass

class OpenPGPVersionException(OpenPGPException):
	def __init__(self, value, triedVersion, validVersions):
		msg = "version of " + value + " can't be " + str(triedVersion) + " must be " + ', '.join(map(str, validVersions))
		super(OpenPGPVersionException, self).__init__(msg)

class OpenPGPIncorrectException(OpenPGPException):
	def __init__(self, incorrect, value, actual, expected):
		msg = incorrect + " is incorrect the " + value + " is " + binascii.hexlify(actual) + " and must be " + binascii.hexlify(expected)
		super(OpenPGPIncorrectException, self).__init__(msg)

class OpenPGPKeyIdException(OpenPGPException):
	def __init__(self, keyId, numKeys):
		if numKeys > 0:
			msg = "Has " + str(numKeys) + " keys but none of them has the keyId equals as " + binascii.hexlify(keyId) + ", signature cannot be validated."
		else:
			msg = "You do not have any keys, signature cannot be validated."
		super(OpenPGPKeyIdException, self).__init__(msg)
