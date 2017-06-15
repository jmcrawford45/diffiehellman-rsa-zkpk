import random

#Step 1 of the protocol is to establish a cyclic group
PRIME = 216551 # In a real implementation, a large prime should be used
GENERATOR = 11

class DH:
	def getPrime(self):
		return PRIME

	def getGen(self):
		return GENERATOR

	def getRandomElement(self):
		return random.SystemRandom().randint(1, PRIME)

	"""
	Calculate 1. step to the secret
	"""
	def getPublic(self, secret):
		return (GENERATOR ** secret) % PRIME

	"""
	Calculate the shared secret
	"""
	def getShared(self, secret, public):
		return (public ** secret) % PRIME
