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
import requests

from tkinter import messagebox as mbox
from datetime import datetime
from dotenv import load_dotenv
import os
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey

import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, popOne, getOne
from utilities.GUI_Utilities import reloadOptionMenu, createIdsAndString
from utilities.communicationToRPC import rpcCall, apiCall

class App():
    def __init__(self):
        global root
        global Credential_list, credentialSelection, credential_menu
        global Request_list, requestSelection, request_menu
        global Response_list, responseSelection, response_menu
        global Lock_key_list, lock_key_Selection, lock_key_menu
        global bankPrivateECKey, bankPublicECKey, compressedPublicECKey, cv

        root = Tk()
        root.geometry('330x500')

        root.configure(bg='red2')
        root.title('Issuer credential app')

        cv = Curve.get_curve("Ed25519")
        g = cv.generator
        p = cv.field
        q = cv.order
        bankPrivateECKey = 8922796882388619604127911146068705796569681654940873967836428543013949233636
        bankPublicECKey = cv.mul_point(bankPrivateECKey, g)
        compressedPublicECKey = cv.encode_point(bankPublicECKey).hex()

        Credential_list = [
        ""
        ]

        Request_list = [
        ""
        ]

        Response_list = [
        ""
        ]

        Lock_key_list = [
        ""
        ]


        b0 = ttk.Button(
            root, text="Retrieve credential request",
            command=self.requestRetrieve)
        b0.grid(row=1, sticky='ew', pady=(11, 7), padx=(25, 0))

        requestSelection = StringVar(root)
        requestSelection.set(Request_list[0])  # default value

        request_menu = OptionMenu(root, requestSelection, *Request_list)
        request_menu.grid(row=2, sticky='ew', pady=(11, 7), padx=(25, 0))

        b1 = ttk.Button(
            root, text="Generate credential",
            command=self.generateCredential)
        b1.grid(row=3, sticky='ew', pady=(11, 7), padx=(25, 0))

        credentialSelection = StringVar(root)
        credentialSelection.set(Credential_list[0])  # default value

        credential_menu = OptionMenu(
            root, credentialSelection, *Credential_list)
        credential_menu.grid(row=4, sticky='ew', pady=(11, 7), padx=(25, 0))

        b2 = ttk.Button(
            root, text="Encrypt credential on SGX",
            command=self.encryptOnSgx)
        b2.grid(row=5, sticky='ew', pady=(11, 7), padx=(25, 0))

        responseSelection = StringVar(root)
        responseSelection.set(Response_list[0])  # default value

        response_menu = OptionMenu(
            root, responseSelection, *Response_list)
        response_menu.grid(row=6, sticky='ew', pady=(11, 7), padx=(25, 0))

        b3 = ttk.Button(
            root, text="      Send credential to customer     ",
            command=self.sendCredential)
        b3.grid(row=7, sticky='ew', pady=(11, 7), padx=(25, 0))

        b4 = ttk.Button(
            root, text="Retrieve unlock request",
            command=self.retrieveLockKeys)
        b4.grid(row=8, sticky='ew', pady=(11, 7), padx=(25, 0))

        lock_key_Selection = StringVar(root)
        lock_key_Selection.set(Lock_key_list[0])  # default value

        lock_key_menu = OptionMenu(
            root, lock_key_Selection, *Lock_key_list)
        lock_key_menu.grid(row=9, sticky='ew', pady=(11, 7), padx=(25, 0))

        b4 = ttk.Button(
            root, text="Retrieve and send unlock key",
            command=self.sendUnlockKey)
        b4.grid(row=10, sticky='ew', pady=(11, 7), padx=(25, 0))

        img_logo = ImageTk.PhotoImage(Image.open(
            "./images/santander-logo-13.png"))
        panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        panel_logo_1.grid(row=11, sticky=S, pady=(10, 0))


        plain_credential_list = getAll("credentials_issuer", "plain_credentials")

        _, usable_ids = createIdsAndString(plain_credential_list, True, "Type", "Name", " for ", subName="Credential")
        reloadOptionMenu(credentialSelection, credential_menu, usable_ids)

        enc_credential_list = getAll("credentials_issuer", "encrypted_credentials")

        _, usable_ids = createIdsAndString(enc_credential_list, True, "Type", "Name", " for ", subName="Credential", endingLabel="(encrypted)")
        reloadOptionMenu(responseSelection, response_menu, usable_ids)

        list_waiting_requests = getAll("credentials_request", "request")
        
        _, usable_ids = createIdsAndString(list_waiting_requests, False, "type", "name", " for ")
        reloadOptionMenu(requestSelection, request_menu, usable_ids)

        list_waiting_lock_keys = getAll("lock_keys_issuer", "lock_keys")
        
        _, usable_ids = createIdsAndString(list_waiting_lock_keys, False, "key", "DID", " for ")
        reloadOptionMenu(lock_key_Selection, lock_key_menu, usable_ids)

        root.mainloop()

    def requestRetrieve(self):
        global Request_list, requestSelection, request_menu

        pendingRequests_json = rpcCall("pendingRequests")

        setMultiple("credentials_request", "request", pendingRequests_json["result"]["request"]) 

        list_waiting_requests = pendingRequests_json["result"]["request"]
        complete_list_requests = getAll("credentials_request", "request")

        aux_str, _ = createIdsAndString(list_waiting_requests, False, "type", "name", " for ")
        if aux_str == "":
            aux_str = "No requests pending"

        else:
            _, usable_ids = createIdsAndString(complete_list_requests, False, "type", "name", " for ")
            reloadOptionMenu(requestSelection, request_menu, usable_ids)

        mbox.showinfo("Result", aux_str)

    def generateCredential(self):
        global plain_credential_list
        global Credential_list, credentialSelection, credential_menu
        global Request_list, requestSelection, request_menu

        requestPosition = requestSelection.get()
        position = int(requestPosition.split(':')[0])

        credential_request = json.dumps(popOne("credentials_request", "request", position))
        list_waiting_req_memory = getAll("credentials_request", "request")

        #reset dropdown for requests
        _, usable_ids_req = createIdsAndString(list_waiting_req_memory, False, "type", "name", " for ")
        reloadOptionMenu(requestSelection, request_menu, usable_ids_req)

        res_json = apiCall("issue", credential_request)
        res_json["Issuer name"] = "Banco Santander"

        res_str = json.dumps(res_json)

        setOne("credentials_issuer", "plain_credentials", res_str)
        plain_credential_list = getAll("credentials_issuer", "plain_credentials")

        aux_str, usable_ids = createIdsAndString(plain_credential_list, True, "Type", "Name", " for ", subName="Credential")
        
        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            reloadOptionMenu(credentialSelection, credential_menu, usable_ids)
            aux_str = "Credential generated"

        mbox.showinfo("Result", json.dumps(res_json, indent=4))

    def encryptOnSgx(self):
        global Response_list, responseSelection, response_menu
        global Credential_list, credentialSelection, credential_menu

        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        data = popOne("credentials_issuer", "plain_credentials", position)
        data_json = json.loads(data)
        print(compressedPublicECKey)
        data_json["Issuer public key"]["Issuer Public key"] = compressedPublicECKey
        data = json.dumps(data_json)
        plain_credential_list = getAll("credentials_issuer" ,"plain_credentials")
        req_json = res_json = apiCall("submit", data, 'scorebytes')
        req_str = json.dumps(req_json)

        _, usable_ids_plain = createIdsAndString(plain_credential_list, True, "Type", "Name", " for ", subName="Credential")
        reloadOptionMenu(credentialSelection, credential_menu, usable_ids_plain)

        setOne("credentials_issuer", "encrypted_credentials", req_str)

        enc_credential_list = getAll("credentials_issuer" ,"encrypted_credentials")

        aux_str, usable_ids = createIdsAndString(enc_credential_list, True, "Type", "Name", " for ", subName="Credential", endingLabel="(encrypted)")
        
        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            reloadOptionMenu(responseSelection, response_menu, usable_ids)
            aux_str = "Credential encrypted on SGX"

        mbox.showinfo("Result", json.dumps(req_json, indent=4))

    def sendCredential(self):
        global Response_list, responseSelection, response_menu

        enc_credentialPosition = responseSelection.get()
        position = int(enc_credentialPosition.split(':')[0])

        enc_credential = popOne("credentials_issuer", "encrypted_credentials", position)
        enc_cred_list = getAll("credentials_issuer", "encrypted_credentials")

        _, usable_ids_enc = createIdsAndString(enc_cred_list, True, "Type", "Name", " for ", subName="Credential", endingLabel="(encrypted)")
        reloadOptionMenu(responseSelection, response_menu, usable_ids_enc)

        print(enc_credential)
        pendingRequests_json = rpcCall("credential", enc_credential)
        print(pendingRequests_json)

        mbox.showinfo("Result", "Credential sent to user")

    def retrieveLockKeys(self):
        global Lock_key_list, lock_key_Selection, lock_key_menu

        pendingLockKeys_json = rpcCall("pendingLockKeys")

        setMultiple("lock_keys_issuer", "lock_keys", pendingLockKeys_json["result"]["lock_keys"]) 

        list_waiting_lock_keys = pendingLockKeys_json["result"]["lock_keys"]
        complete_list_lock_keys = getAll("lock_keys_issuer", "lock_keys")

        aux_str, _ = createIdsAndString(list_waiting_lock_keys, False, "key", "DID", " for ")
        if aux_str == "":
            aux_str = "No requests pending"

        else:
            _, usable_ids = createIdsAndString(complete_list_lock_keys, False, "key", "DID", " for ")
            reloadOptionMenu(lock_key_Selection, lock_key_menu, usable_ids)

        mbox.showinfo("Result", aux_str)

    def sendUnlockKey(self):
        global Lock_key_list, lock_key_Selection, lock_key_menu
        global bankPrivateECKey, bankPublicECKey, compressedPublicECKey, cv


        lock_keyPosition = lock_key_Selection.get()
        position = int(lock_keyPosition.split(':')[0])

        lock_key_json = popOne("lock_keys_issuer", "lock_keys", position)
        lock_keys_list = getAll("lock_keys_issuer", "lock_keys")

        lock_key_compressed = lock_key_json["key"]
        lock_key_x, lock_key_y = self.uncompressKey(lock_key_compressed)

        eph_pub_key  = Point(lock_key_x,lock_key_y,cv)

        unlock_key_int = cv.mul_point(bankPrivateECKey, eph_pub_key).x
        unlock_key = hex(unlock_key_int)
        print("Hola")
        print(unlock_key)

        pendingRequests_json = rpcCall("unlockKey", {"DID": "1111", "unlock_key": unlock_key[2:], "lock_key": lock_key_compressed})

        _, usable_ids = createIdsAndString(lock_keys_list, False, "key", "DID", " for ")
        reloadOptionMenu(lock_key_Selection, lock_key_menu, usable_ids)

        mbox.showinfo("Result", "Unlock key sent")

    def uncompressKey(self,compressedKey):
        compKey_bytes = bytes.fromhex(compressedKey)
        compKey_sign = compKey_bytes[31] & 128

        compKey_barray = bytearray(compKey_bytes)

        compKey_barray[31] &= 127
        compKey_barray.reverse()

        comp_key_rev = bytes(compKey_barray)
        comp_key_int = int.from_bytes(comp_key_rev, "big")

        recoveredXCoord = cv.x_recover(comp_key_int, (compKey_sign>0))
        return recoveredXCoord, comp_key_int

def main():
    App()

    return 0


if __name__ == '__main__':
    main()
