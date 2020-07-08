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
import Padding

from tkinter import messagebox as mbox
from datetime import datetime
from dotenv import load_dotenv
import os

import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, popOne, getOne
from utilities.GUI_Utilities import reloadOptionMenu, createIdsAndString, createIdsAndStringSpecialCase
from utilities.communicationToRPC import rpcCall



class App():
    def __init__(self):
        global root
        global Presentation_List, presentationSelection, presentation_menu
        global PreWithKey_list, preWithKeySelection, preWithKey_menu
        global Plain_list, plainSelection, plain_menu

        root = Tk()
        root.geometry('330x500')

        root.configure(bg='green')
        root.title('Service Provider app')

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
            root, text="Check encrypted presentation info",
            command=self.checkInfoEnc)
        b2.grid(row=3, sticky='ew', pady=(11, 7), padx=(25, 0))

        b3 = ttk.Button(
            root, text="Ask for unlock key",
            command=self.askUnlockKey)
        b3.grid(row=4, sticky='ew', pady=(11, 7), padx=(25, 0))

        b4 = ttk.Button(
            root, text="Retrieve pending unlock keys",
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
            root, text="Check plain presentation info",
            command=self.checkInfoPlain)
        b6.grid(row=9, sticky='ew', pady=(11, 7), padx=(25, 0))


        img_logo = ImageTk.PhotoImage(Image.open(
            "./images/santander-logo-13.png"))
        panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        panel_logo_1.grid(row=10,sticky=S, pady=(10, 0))

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

        mbox.showinfo("Result", aux_str)

    def checkInfoEnc(self):
        global presentationSelection

        credentialPosition = presentationSelection.get()
        position = int(credentialPosition.split(':')[0])

        enc_credential_list = getAll("credentials_serviceP", "encrypted_credentials")

        parsed = enc_credential_list[position]
        mbox.showinfo("Result", json.dumps(parsed, indent=4))

    def askUnlockKey(self):
        global Presentation_List, presentationSelection, presentation_menu

        presentationPosition = presentationSelection.get()
        position = int(presentationPosition.split(':')[0])
        enc_credential = getOne("credentials_serviceP", "encrypted_credentials", position)

        pendingRequests_json = rpcCall("lockKey", {"DID": "4567", "key": enc_credential["Credential"]["lock key"]["value"]})

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

        encrypted_value_str = enc_credential_withK["Credential"]["score"]["value"]
        encrypted_value_hex = base64.b64decode(encrypted_value_str).hex()
        encrypted_value_bytes = bytes.fromhex(encrypted_value_hex)
        encrypted_value_barray = bytearray(encrypted_value_bytes)
        AESSymmetricKey = enc_credential_withK["Credential"]["unlock key"]

        formatedAESSymmetricKeyPrime = hashlib.sha256(str(int("0x" + AESSymmetricKey, 16)).encode()).digest()

        padded_decrypted_str = self.aux_decrypt(encrypted_value_barray,formatedAESSymmetricKeyPrime,AES.MODE_GCM)
        print(padded_decrypted_str)
        print(bytes(padded_decrypted_str[16:]))
        decrypted_str = Padding.removePadding(padded_decrypted_str.decode(),mode=0)
        print(decrypted_str)
        #enc_credential_withK["Credential"]["score"]["value"] = decrypted_str
        #enc_credential_withK["Credential"]["score"]["encrypted"] = False

        #setOne("credentials_serviceP","plain_credentials", enc_credential_withK)
        
        #plain_credentials_list = getAll("credentials_serviceP","plain_credentials")
        #_, usable_ids = createIdsAndString(plain_credentials_list, False, "Type", "Name", " for ", subName="Credential", endingLabel="(plain)")
        #reloadOptionMenu(plainSelection, plain_menu, usable_ids)

    def aux_decrypt(self,ciphertext,key, mode):
        encobj = AES.new(key,mode)
        return(encobj.decrypt(ciphertext))
        

    def checkInfoPlain(self):
        global plainSelection

        credentialPosition = plainSelection.get()
        position = int(credentialPosition.split(':')[0])

        plain_credential_list = getAll("credentials_serviceP", "plain_credentials")

        parsed = plain_credential_list[position]
        mbox.showinfo("Result", json.dumps(parsed, indent=4))


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
