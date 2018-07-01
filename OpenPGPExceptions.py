import binascii

class OpenPGPVersionException(Exception):
	def __init__(self, value, triedVersion, validVersions):
		msg = "version of " + value + " can't be " + str(triedVersion) + " must be " + ', '.join(map(str, validVersions))
		super(OpenPGPVersionException, self).__init__(msg)

class OpenPGPIncorrectException(Exception):
	def __init__(self, incorrect, value, actual, expected):
		msg = incorrect + " is incorrect the " + value + " is " + binascii.hexlify(actual) + " and must be " + binascii.hexlify(expected)
		super(OpenPGPIncorrectException, self).__init__(msg)
