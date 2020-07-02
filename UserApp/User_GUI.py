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
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

from tkinter import messagebox as mbox
from datetime import datetime
from dotenv import load_dotenv
import os

import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, deleteOne
from utilities.GUI_Utilities import reloadOptionMenu, createIdsAndString



class App():
    def __init__(self):
        global root
        global Credential_list, credentialSelection, credential_menu
        global e1
        global memory_credential_list
        global ClientRSAkeyPair

        root = Tk()
        root.geometry('300x500')

        root.configure(bg='red2')
        root.title('User credential wallet')

        ClientRSAkeyPair_PEM = open("client.key", "r").read()
        ClientRSAkeyPair = RSA.import_key(ClientRSAkeyPair_PEM)

        Credential_list = [
        ""
        ]

        credentialType_list = [
        "Good payer cert",
        "Account ownership cert",
        "Average account balance cert"
        ]

        ttk.Label(
            root, text="Name: Alice      DID: 1234").grid(
                row=1, sticky='ew', pady=(11, 7), padx=(25,0))

        b1 = ttk.Button(
            root, text="Synchronize credentials",
            command=self.showListCredentials)
        b1.grid(row=2, sticky='ew', pady=(11, 7), padx=(25, 0))

        credentialSelection = StringVar(root)
        credentialSelection.set(Credential_list[0]) # default value

        credential_menu = OptionMenu(root, credentialSelection, *Credential_list)
        credential_menu.grid(row=3, sticky='ew', pady=(11, 7), padx=(25, 0))

        b2 = ttk.Button(
            root, text="Check credential info",
            command=self.check_cred_info)
        b2.grid(row=4, sticky='ew', pady=(11, 7), padx=(25, 0))

        e1 = StringVar(root)
        e1.set(credentialType_list[0]) # default value

        credTypes_menu = OptionMenu(root, e1, *credentialType_list)
        credTypes_menu.grid(row=5, sticky='ew', pady=(11, 7), padx=(25, 0))

        b3 = ttk.Button(
            root, text="      Ask for a new credential      ",
            command=self.askNewCredential)
        b3.grid(row=6, sticky='ew', pady=(11, 7), padx=(25, 0))


        img_logo = ImageTk.PhotoImage(Image.open(
            "./images/santander-logo-13.png"))
        panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        panel_logo_1.grid(row=7,sticky=S, pady=(10, 0))

        credential_list = getAll("credentials_saved", "credentials")

        _, usable_ids = createIdsAndString(credential_list, False, "Type", "Issuer name", " by ", subName="Credential")
        reloadOptionMenu(credentialSelection, credential_menu, usable_ids)

        root.mainloop()

    def showListCredentials(self):
        global memory_credential_list
        global Credential_list, credentialSelection, credential_menu
        global ClientRSAkeyPair


        decryptor = PKCS1_OAEP.new(ClientRSAkeyPair,hashAlgo=SHA256 ,label="Encrypted with Public RSA key".encode('utf8'))
        
        data = {
           "jsonrpc": "2.0",
           "method": "pendingCredentials",
           "id": 1,
           "params": []
        }
        avaliableCredentials = requests.post('http://localhost:3000/jsonrpc' , data=json.dumps(data))
        avaliableCredentials_json = avaliableCredentials.json()
        get_credentials_list = avaliableCredentials_json["result"]["credentials"]
        
        for i in range (0, len(get_credentials_list)):
            getCred_json = get_credentials_list[i]
            print(get_credentials_list[0]["Credential"]["lock key"]["encrypted"])
            if getCred_json["Credential"]["lock key"]["encrypted"]:
                lock_key_enc = getCred_json["Credential"]["lock key"]["value"]
                lock_key_enc_bytes = binascii.a2b_base64(lock_key_enc)
                print(lock_key_enc_bytes)
                lock_key_dec_bytes = decryptor.decrypt(lock_key_enc_bytes)
                print(lock_key_dec_bytes)
                getCred_json["Credential"]["lock key"]["value"] = lock_key_dec_bytes.decode("utf-8") 
                getCred_json["Credential"]["lock key"]["encrypted"] = False
                get_credentials_list[i] = getCred_json



        setMultiple("credentials_saved", "credentials", get_credentials_list)

        memory_credential_list = getAll("credentials_saved", "credentials")

        new_credential_list = avaliableCredentials_json["result"]["credentials"] # Lista descargada

        aux_str, _ = createIdsAndString(new_credential_list, False, "Type", "Issuer name", " by ", subName="Credential")
        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            _, usable_ids = createIdsAndString(memory_credential_list, False, "Type", "Issuer name", " by ", subName="Credential")
            reloadOptionMenu(credentialSelection, credential_menu, usable_ids)

        mbox.showinfo("Result", aux_str)

    def check_cred_info(self):
        global credentialSelection
        global memory_credential_list

        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        parsed = memory_credential_list[position]
        mbox.showinfo("Result", json.dumps(parsed, indent=4))
        
    def askNewCredential(self):
        global e1

        data = {
            "jsonrpc": "2.0",
            "method": "credentialRequest",
            "id": 1,
            "params": [{"name": "Alice", "type": e1.get(), "DID": "1234"}]
        }
        pendingRequests = requests.post('http://localhost:3000/jsonrpc' , data=json.dumps(data))
        pendingRequests_json = pendingRequests.json()
        print(pendingRequests_json)


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
