from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from Crypto.Cipher import AES
import binascii
import os
import sha3
import time
import hashlib

import json

cv = Curve.get_curve('bn256')
g = cv.generator
q = cv.order
p = cv.field

cvEd = Curve.get_curve('Ed25519')
gEd = cvEd.generator

class DataIntegrityError(Exception):
    pass

def getRandomNumber():
    return int(binascii.hexlify(os.urandom(32)).decode("utf-8"), 16)

def createKeyPair():
    ephPrivK = getRandomNumber()
    ephPubK = cv.mul_point(ephPrivK, g)

    print("KEYPAIR", ephPrivK, ephPubK.x, ephPubK.y)

    return [ephPrivK, ephPubK.x, ephPubK.y]

def gettT(privK, pubKX, pubKY):
    Point(pubKX,pubKY,cv)

def decrypt(key, ciphertext: bytes) -> bytes:
    """Return plaintext for given ciphertext."""

    # Split out the nonce, tag, and encrypted data.
    nonce = ciphertext[:12]
    if len(nonce) != 12:
        raise DataIntegrityError("Cipher text is damaged: invalid nonce length")

    tlen = len(ciphertext) - 16
    if tlen < 12:
        raise DataIntegrityError("Cipher text is damaged: too short")

    encrypted = ciphertext[12: tlen]
    tag = ciphertext[tlen:]
    if len(tag) != 16:
        raise DataIntegrityError("Cipher text is damaged: invalid tag length")

    # Construct AES cipher, with old nonce.
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    # Decrypt and verify.
    try:
        plaintext = cipher.decrypt_and_verify(encrypted, tag)  # type: ignore
    except ValueError as e:
        raise DataIntegrityError("Cipher text is damaged: {}".format(e))
    return plaintext

def verify(message, pbkey, signature):
    # sign contains R i s (32 bytes each)
    # Verify:
    # R + hash(R+m)Pb == sG
    keybytes =  bytes.fromhex(pbkey)
    sigbytes = bytes.fromhex(signature)
    R = sigbytes[:32]
    s = sigbytes[32:]

    #calculate the hash
    h = hashlib.sha256()
    h.update(R)
    h.update(message.encode("utf-8"))

    hint = int.from_bytes(h.digest(),"little")


    si = int.from_bytes(s, "little")
    S = cv.mul_point(si,g)

    Rp = cv.decode_point(R)
    Pb = cv.decode_point(keybytes)

    X = cv.add_point(Rp, cv.mul_point(hint, Pb))
    return (X.eq(S))


def calculateSymKey(lock_key_compressed, bankPrivateECKey):
    lock_key_x, lock_key_y = uncompressKey(lock_key_compressed)

    eph_pub_key  = Point(lock_key_x,lock_key_y,cv)

    unlock_key = cv.mul_point(bankPrivateECKey, eph_pub_key)
    comp_key = cv.encode_point(unlock_key).hex()
    print(unlock_key)
    return comp_key


def uncompressKey(compressedKey):
    compKey_bytes = bytes.fromhex(compressedKey)
    compKey_sign = compKey_bytes[31] & 128

    compKey_barray = bytearray(compKey_bytes)

    compKey_barray[31] &= 127
    compKey_barray.reverse()

    comp_key_rev = bytes(compKey_barray)
    comp_key_int = int.from_bytes(comp_key_rev, "big")

    recoveredXCoord = cv.x_recover(comp_key_int, (compKey_sign>0))
    return recoveredXCoord, comp_key_int

def getCompressedPubFromPriv(privECKey):
    return cvEd.encode_point(cvEd.mul_point(privECKey, gEd)).hex()

def getPackedPubFromPriv(privECKey):
    publicECKey = cv.mul_point(privECKey, g)
    paddedX = hex(publicECKey.x)[2:]
    while len(paddedX) < 64:
        paddedX = '0' + paddedX

    paddedY = hex(publicECKey.y)[2:]
    while len(paddedY) < 64:
        paddedY = '0' + paddedY

    return (paddedX + paddedY)

def calulateUnlockAndMaskedUnlock(privECKey, lockKeyPacked):
    lockKey = Point(int(lockKeyPacked[:64], 16), int(lockKeyPacked[64:], 16), cv)
    unlockKey = cv.mul_point(privECKey, lockKey)
    return (unlockKey, cv.mul_point(unlockKey.x, g))

def calculateChallenge(spEphPrivK, issEphPubKX, issEphPubKY, Tx, Ty):

    print("PUBKEY", issEphPubKX, issEphPubKY)

    data = str(cv.mul_point(spEphPrivK, Point(issEphPubKX, issEphPubKY, cv)).x)
    spHash = int(sha3.sha3_224(data.encode('utf-8')).hexdigest(), 16)
    return cv.add_point(cv.mul_point(spHash, g), Point(Tx, Ty, cv)).x

# bankPrivateECKey = 8922796882388619604127911146068705796569681654940873967836428543013949233636 % p

# bankPublicECKey = cv.mul_point(bankPrivateECKey, g)


# print(len(hex(bankPublicECKey.x)))
# print(len(hex(bankPublicECKey.y)))
# print(bankPrivateECKey)
# print('0' + hex(bankPublicECKey.x)[2:] + '0' + hex(bankPublicECKey.y)[2:])



# print(bankPublicECKey)