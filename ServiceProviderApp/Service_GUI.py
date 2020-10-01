#!/usr/bin/env python

# Copyright 2019 Banco Santander S.A.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-

from tkinter import *
from tkinter import ttk, _setit
from PIL import ImageTk, Image
from tkinter.filedialog import askopenfilename, asksaveasfilename
import json
import uuid
import base64
import time
import hashlib
import requests
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa      import ECDSA
import Padding

from tkinter import messagebox as mbox
from datetime import datetime
from dotenv import load_dotenv
import os

import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, popOne, getOne
from utilities.GUI_Utilities import reloadOptionMenu, createIdsAndString, createIdsAndStringSpecialCase
from utilities.communicationToRPC import rpcCall, apiCall, apiCallSgxHard
from crypto_local.encForSgx import encryptSGXWorkOrder

class DataIntegrityError(Exception):
    pass


class App():
    def __init__(self):
        global root
        global Presentation_List, presentationSelection, presentation_menu
        global PreWithKey_list, preWithKeySelection, preWithKey_menu
        global Plain_list, plainSelection, plain_menu
        global cv, g,p,q
        global SGX_req_workerRet, SGX_req_json

        root = Tk()
        root.geometry('330x540')

        root.configure(bg='green')
        root.title('Bankia app')

        cv = Curve.get_curve("Ed25519")
        g = cv.generator
        p = cv.field
        q = cv.order

        SGX_req_json = {
        "jsonrpc": "2.0", 
        "method": "WorkOrderSubmit", 
        "id": 11, 
        "params": {
            "responseTimeoutMSecs": 6000, 
            "payloadFormat": "JSON-RPC", 
            "resultUri": "resulturi", 
            "notifyUri": "notifyuri", 
            "workOrderId": "", 
            "workerId": "0b03616a46ea9cf574f3f8eedc93a62c691a60dbd3783427c0243bacfe5bba94", 
            "workloadId": "", 
            "requesterId": "0x3456", 
            "dataEncryptionAlgorithm": "AES-GCM-256", 
            "encryptedSessionKey": "", 
            "sessionKeyIv": "", 
            "requesterNonce": "", 
            "encryptedRequestHash": "", 
            "requesterSignature": "", 
            "inData": [
                {"index": 1, 
                "data": "", 
                "encryptedDataEncryptionKey": "", 
                "iv": ""}
            ]
            }
        }

        SGX_req_workerRet = {"jsonrpc": "2.0", "method": "WorkerRetrieve", "id": 2, "params": {"workerId": "0b03616a46ea9cf574f3f8eedc93a62c691a60dbd3783427c0243bacfe5bba94"}}

        Presentation_list = [
        ""
        ]

        PreWithKey_list = [
        ""
        ]

        Plain_list = [
        ""
        ]

        b1 = ttk.Button(
            root, text="Retrieve user presentations",
            command=self.retrieveUserCredentials)
        b1.grid(row=1, sticky='ew', pady=(11, 7), padx=(25, 0))

        presentationSelection = StringVar(root)
        presentationSelection.set(Presentation_list[0]) # default value

        presentation_menu = OptionMenu(root, presentationSelection, *Presentation_list)
        presentation_menu.grid(row=2, sticky='ew', pady=(11, 7), padx=(25, 0))

        b2 = ttk.Button(
            root, text="View encrypted presentation info",
            command=self.checkInfoEnc)
        b2.grid(row=3, sticky='ew', pady=(11, 7), padx=(25, 0))

        b3 = ttk.Button(
            root, text="Ask for unlock key",
            command=self.askUnlockKey)
        b3.grid(row=4, sticky='ew', pady=(11, 7), padx=(25, 0))

        b4 = ttk.Button(
            root, text="Retrieve last unlock keys",
            command=self.retrievePendingUnlock)
        b4.grid(row=5, sticky='ew', pady=(11, 7), padx=(25, 0))

        preWithKeySelection = StringVar(root)
        preWithKeySelection.set(PreWithKey_list[0]) # default value

        preWithKey_menu = OptionMenu(root, preWithKeySelection, *PreWithKey_list)
        preWithKey_menu.grid(row=6, sticky='ew', pady=(11, 7), padx=(25, 0))

        b5 = ttk.Button(
            root, text="Decrypt presentation",
            command=self.decryptPresent)
        b5.grid(row=7, sticky='ew', pady=(11, 7), padx=(25, 0))

        plainSelection = StringVar(root)
        plainSelection.set(Plain_list[0]) # default value

        plain_menu = OptionMenu(root, plainSelection, *Plain_list)
        plain_menu.grid(row=8, sticky='ew', pady=(11, 7), padx=(25, 0))

        b6 = ttk.Button(
            root, text="View plain presentation info",
            command=self.checkInfoPlain)
        b6.grid(row=9, sticky='ew', pady=(11, 7), padx=(25, 0))

        b7 = ttk.Button(
            root, text="Validate signature",
            command=self.validateSignature)
        b7.grid(row=10, sticky='ew', pady=(11, 7), padx=(25, 0))


        enc_credential_list = getAll("credentials_serviceP", "encrypted_credentials")

        _, usable_ids = createIdsAndString(enc_credential_list, False, "Type", "Name", " for ", subName="Credential")
        reloadOptionMenu(presentationSelection, presentation_menu, usable_ids)

        enc_credentia_withK_list = getAll("credentials_serviceP", "encrypted_credentials_withK")

        _, usable_ids = createIdsAndString(enc_credentia_withK_list, False, "Type", "Name", " for ", subName="Credential", endingLabel="(with key)")
        reloadOptionMenu(preWithKeySelection, preWithKey_menu, usable_ids)

        plain_credential_list = getAll("credentials_serviceP", "plain_credentials")

        _, usable_ids = createIdsAndString(plain_credential_list, False, "Type", "Name", " for ", subName="Credential", endingLabel="(decrypted)")
        reloadOptionMenu(plainSelection, plain_menu, usable_ids)

        root.mainloop()

    def retrieveUserCredentials(self):
        global Presentation_List, presentationSelection, presentation_menu

        presentations_json = rpcCall("pendingPresentations")
        print(presentations_json)

        setMultiple("credentials_serviceP", "encrypted_credentials", presentations_json["result"]["presentations"]) 

        list_waiting_presentations = presentations_json["result"]["presentations"]
        complete_list_presentations = getAll("credentials_serviceP", "encrypted_credentials")

        aux_str, _ = createIdsAndString(list_waiting_presentations, False, "Type", "Name", " for ", subName="Credential")
        if aux_str == "":
            aux_str = "No presentations pending"

        else:
            _, usable_ids = createIdsAndString(complete_list_presentations, False, "Type", "Name", " for ", subName="Credential")
            reloadOptionMenu(presentationSelection, presentation_menu, usable_ids)

        mbox.showinfo("Result", "User presentations retrieved")

    def checkInfoEnc(self):
        global presentationSelection

        credentialPosition = presentationSelection.get()
        position = int(credentialPosition.split(':')[0])

        enc_credential_list = getAll("credentials_serviceP", "encrypted_credentials")

        parsed = enc_credential_list[position]

        RSA_key = parsed["Subject Public key"]
        RSA_key_Shortened = RSA_key[:40] + "...." + RSA_key[-40:]
        parsed["Subject Public key"] = RSA_key_Shortened

        issuer_signature = parsed["IssuerSignature"]
        issuer_signature_short = issuer_signature[:8] + "...." + issuer_signature[-8:]
        parsed["IssuerSignature"] = issuer_signature_short

        mbox.showinfo("Result", json.dumps(parsed, indent=4))

    def askUnlockKey(self):
        global Presentation_List, presentationSelection, presentation_menu

        presentationPosition = presentationSelection.get()
        position = int(presentationPosition.split(':')[0])
        enc_credential = getOne("credentials_serviceP", "encrypted_credentials", position)

        SGX_worker_info = apiCallSgxHard(SGX_req_workerRet)

        temp_SGX_json = SGX_req_json
        workloadId = "heart-disease-eval"
        workOrderId = "0x" + uuid.uuid4().hex[:16]
        temp_SGX_json["params"]["workOrderId"] = workOrderId
        temp_SGX_json["params"]["workloadId"] = workloadId.encode("UTF-8").hex()
        lock_key_compressed = enc_credential["Credential"]["lock key"]["value"]
        lock_key_x, lock_key_y = self.uncompressKey(lock_key_compressed)
        temp_SGX_json["params"]["inData"][0]["data"] = "unlock:"+lock_key_x+"-"+lock_key_y
        SGX_json_enc, enc_session_json = encryptSGXWorkOrder(temp_SGX_json, SGX_worker_info)
        SGX_response = apiCallSgxHard(json.loads(SGX_json_enc))

        mbox.showinfo("Result", "Unlock key request sent")

    def retrievePendingUnlock(self):
        global PreWithKey_list, preWithKeySelection, preWithKey_menu

        unlock_json = rpcCall("pendingUnlockKeys")
        print(unlock_json)
        unlock_keys_list = unlock_json["result"]["unlock_keys"]
        lock_keys = list()
        unlock_keys = list()
        for unlock_key in unlock_keys_list:
            lock_keys.append(unlock_key["lock_key"])
            unlock_keys.append(unlock_key["unlock_key"])

        enc_credential_list = getAll("credentials_serviceP", "encrypted_credentials")

        for enc_cred in enc_credential_list:
            for i in range (0, len(lock_keys)):
                if enc_cred["Credential"]["lock key"]["value"] == lock_keys[i]:
                    enc_cred["Credential"]["unlock key"] = unlock_keys[i]
                    setOne("credentials_serviceP", "encrypted_credentials_withK", enc_cred)

 
        complete_list_withUnlock = getAll("credentials_serviceP", "encrypted_credentials_withK")

        _, usable_ids = createIdsAndString(complete_list_withUnlock, False, "Type", "Name", " for ", subName="Credential", endingLabel="(with key)")
        reloadOptionMenu(preWithKeySelection, preWithKey_menu, usable_ids)
        
        mbox.showinfo("Result", "Unlock keys syncronized") #Revisar

    def decryptPresent(self):
        global PreWithKey_list, preWithKeySelection, preWithKey_menu
        global Plain_list, plainSelection, plain_menu

        preWithKPosition = preWithKeySelection.get()
        position = int(preWithKPosition.split(':')[0])

        enc_credential_withK = popOne("credentials_serviceP", "encrypted_credentials_withK", position)

        cipher_b64 = enc_credential_withK["IssuerSignature"]
        cipher_bytes = base64.b64decode(cipher_b64)
        key_hex = enc_credential_withK["Credential"]["unlock key"]
        key_bytes = bytes.fromhex(key_hex)
        plain_bytes = self.decrypt(key_bytes, cipher_bytes)
        plaintext = str(plain_bytes, "utf-8")

        enc_credential_withK["IssuerSignature"] = plaintext
        enc_credential_withK["signature encrypted"] = False
        setOne("credentials_serviceP","plain_credentials", enc_credential_withK)
        
        plain_credentials_list = getAll("credentials_serviceP","plain_credentials")
        _, usable_ids = createIdsAndString(plain_credentials_list, False, "Type", "Name", " for ", subName="Credential", endingLabel="(plain)")
        reloadOptionMenu(plainSelection, plain_menu, usable_ids)

        enc_credentia_withK_list = getAll("credentials_serviceP", "encrypted_credentials_withK")

        _, usable_ids = createIdsAndString(enc_credentia_withK_list, False, "Type", "Name", " for ", subName="Credential", endingLabel="(with key)")
        reloadOptionMenu(preWithKeySelection, preWithKey_menu, usable_ids)

        mbox.showinfo("Result", "Presentation decrypted")

    def decrypt(self, key, ciphertext: bytes) -> bytes:
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
        

    def checkInfoPlain(self):
        global plainSelection

        credentialPosition = plainSelection.get()
        position = int(credentialPosition.split(':')[0])

        plain_credential_list = getAll("credentials_serviceP", "plain_credentials")

        parsed = plain_credential_list[position]

        RSA_key = parsed["Subject Public key"]
        RSA_key_Shortened = RSA_key[:40] + "...." + RSA_key[-40:]
        parsed["Subject Public key"] = RSA_key_Shortened

        issuer_signature = parsed["IssuerSignature"]
        issuer_signature_short = issuer_signature[:8] + "...." + issuer_signature[-8:]
        parsed["IssuerSignature"] = issuer_signature_short

        mbox.showinfo("Result", json.dumps(parsed, indent=4))

    def validateSignature(self):
        global Plain_list, plainSelection, plain_menu
        global cv

        plainKPosition = plainSelection.get()
        position = int(plainKPosition.split(':')[0])

        plain_credential = getOne("credentials_serviceP", "plain_credentials", position)

        issuer_pubK_comp = plain_credential["Issuer public key"]
        issuer_signature = plain_credential["IssuerSignature"]
        message = plain_credential["Credential"]["Name"] + plain_credential["Credential"]["DID"] + plain_credential["Credential"]["Type"] + plain_credential["Credential"]["value"] + plain_credential["IssuerDID"]

        valid = self.verify(message,issuer_pubK_comp,issuer_signature)
        print(valid)
        if valid:
            mbox.showinfo("Result", "The signature is valid")
        else:
            mbox.showinfo("Result", "The signature is not valid")


    def uncompressKey(self,compressedKey):
        global cv
        compKey_bytes = bytes.fromhex(compressedKey)
        compKey_sign = compKey_bytes[31] & 128

        compKey_barray = bytearray(compKey_bytes)

        compKey_barray[31] &= 127
        compKey_barray.reverse()

        comp_key_rev = bytes(compKey_barray)
        comp_key_int = int.from_bytes(comp_key_rev, "big")

        recoveredXCoord = cv.x_recover(comp_key_int, (compKey_sign>0))
        return recoveredXCoord, comp_key_int

    def verify(self,message, pbkey, signature):
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



def main():
    App()

    return 0


if __name__ == '__main__':
    main()
