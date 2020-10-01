from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve.publicKey import PublicKey
from Crypto.Hash import SHA256
import codecs
from crypto_local.signature import ClientSignature
import base64
import json


class signAlgorithm(object) :

	def loadKey(self, key_str): ##DONE
		self.privateKey = PrivateKey.fromPem(key_str)

	def getPublicKey(self): ##DONE
		return self.privateKey.publicKey()

	def getPublicKeySerialized(self): ##DONE
		return self.privateKey.publicKey().toPem()


	def sign_message(self,hash_t): ##DONE
		aux_signing = ClientSignature()
		byte_arr = bytes(hash_t)

		hash_obj = SHA256.new()
		hash_obj.update(byte_arr)
		hash_tuple = tuple(list(hash_obj.digest()))

		#Bytearray to base64
		hash_b_arr = bytearray(list(hash_tuple))
		hash_b64 = base64.b64encode(hash_b_arr)
		hash_b64_str = str(hash_b64, 'utf-8')

		signed = Ecdsa.sign(hash_b64_str, self.privateKey)

		return signed

	def verify_signature(self,hash_b64_str, decoded_signature, verify_key):##DONE
		return Ecdsa.verify(hash_b64_str, decoded_signature, verify_key)
