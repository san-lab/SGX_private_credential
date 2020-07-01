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
        #credential_menu.pack()
        credential_menu.grid(row=3, sticky='ew', pady=(11, 7), padx=(25, 0))

        b2 = ttk.Button(
            root, text="Check credential info",
            command=self.check_cred_info)
        b2.grid(row=4, sticky='ew', pady=(11, 7), padx=(25, 0))

        e1 = StringVar(root)
        e1.set(credentialType_list[0]) # default value

        credTypes_menu = OptionMenu(root, e1, *credentialType_list)
        #credential_menu.pack()
        credTypes_menu.grid(row=5, sticky='ew', pady=(11, 7), padx=(25, 0))

        b3 = ttk.Button(
            root, text="      Ask for a new credential      ",
            command=self.askNewCredential)
        b3.grid(row=6, sticky='ew', pady=(11, 7), padx=(25, 0))


        img_logo = ImageTk.PhotoImage(Image.open(
            "./images/santander-logo-13.png"))
        panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        panel_logo_1.grid(row=7,sticky=S, pady=(10, 0))

        credentials_file = open("./credentials_saved.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credential_list = credentials_json["credentials"]

        aux_str = ""
        usable_ids = list()
        for i in range (0,len(credential_list)):
            #cred_json = credential_list[i]
            cred_json = credential_list[i]
            #cred_json = json.loads(cred)
            new_id = str(i) + ": " + cred_json["Credential"]["Type"] + " by " + cred_json["Issuer name"] + "\n"
            usable_ids.append(new_id)
            aux_str = aux_str + new_id + "\n"

        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            credentialSelection.set('')
            credential_menu['menu'].delete(0, 'end')

            # Insert list of new options (tk._setit hooks them up to var)
            count = 0
            for _id in usable_ids:
                credential_menu['menu'].add_command(label=_id, command=_setit(credentialSelection, _id))
                count = count+1

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





        credentials_file = open("./credentials_saved.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)

        credentials_json["credentials"] += get_credentials_list
        memory_credential_list = credentials_json["credentials"]

        print(avaliableCredentials_json["result"]["credentials"])
        new_credential_list = avaliableCredentials_json["result"]["credentials"] # Lista descargada

        credential_file_write = open("./credentials_saved.json", "w")
        credential_file_write.write(json.dumps(credentials_json))
        credential_file_write.close()

        aux_str = ""
        for i in range (0,len(new_credential_list)):
            cred_json = new_credential_list[i]
            new_id = str(i) + ": " + cred_json["Credential"]["Type"] + " by " + cred_json["Issuer name"] + "\n"
            aux_str = aux_str + new_id + "\n"

        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            usable_ids = list()
            for i in range (0,len(memory_credential_list)):
                cred_json = memory_credential_list[i]
                new_id = str(i) + ": " + cred_json["Credential"]["Type"] + " by " + cred_json["Issuer name"] + "\n"
                usable_ids.append(new_id)

            credentialSelection.set('')
            credential_menu['menu'].delete(0, 'end')

            # Insert list of new options (tk._setit hooks them up to var)
            count = 0
            for _id in usable_ids:
                credential_menu['menu'].add_command(label=_id, command=_setit(credentialSelection, _id))
                count = count+1

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
