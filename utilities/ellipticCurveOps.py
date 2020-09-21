from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import binascii
import os
import sha3
import time

import json

cv = Curve.get_curve('bn256')
g = cv.generator
q = cv.order

def getRandomNumber():
    return int(binascii.hexlify(os.urandom(32)).decode("utf-8"), 16)

def createKeyPair():
    ephPrivK = getRandomNumber()
    ephPubK = cv.mul_point(ephPrivK, g)
    return [ephPrivK, ephPubK]