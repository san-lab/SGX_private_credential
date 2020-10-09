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
from tkinter import ttk
from PIL import ImageTk, Image
import json
import base64
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

from tkinter import messagebox as mbox
import os

import sys
sys.path.append('../')
from dao.dao import getAll, setMultiple
from utilities.communicationToRPC import rpcCall
from utilities.GUI_Utilities import (createIdsAndStringSpecialCase,
                                     reloadOptionMenu,
                                     button,
                                     multipleSelect,
                                     loadLists)


class App():
    def __init__(self):
        global root
        global credentialSelection, credential_menu
        global presentationSelection, presentation_menu
        global e1
        global memory_credential_list
        global ClientRSAkeyPair

        root = Tk()
        root.geometry('330x540')

        root.configure(bg='cyan')
        root.title('User credential wallet')

        ClientRSAkeyPair_PEM = open(os.path.dirname(os.path.abspath(__file__)) + '/' + "client.key", "r").read()
        ClientRSAkeyPair = RSA.import_key(ClientRSAkeyPair_PEM)

        Credential_list = [
        ""
        ]

        credentialType_list = [
        "Good payer cert",
        "Account ownership cert",
        "Average account balance cert"
        ]

        Presentation_List = [
        ""
        ]

        ttk.Label(
            root, text="Name: Alice      DID: 1234").grid(
                row=1, sticky='ew', pady=(11, 7), padx=(25,0))
        button(root, "Synchronize credentials", 2, self.syncCredentials)
        credentialSelection, credential_menu = multipleSelect(root, Credential_list, 3)
        button(root, "View credential info", 4, self.check_cred_info)
        credTypesSelection, credTypes_menu = multipleSelect(root, credentialType_list, 5)
        button(root, "      Ask for a new credential      ", 6, self.askNewCredential)
        presentationSelection, presentation_menu = multipleSelect(root, Presentation_List, 7)
        button(root, "Send presentation to service provider", 8, self.sendToServiceProvider)


        #img_logo = ImageTk.PhotoImage(Image.open(
        #    "./images/santander-logo-13.png"))
        #panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        #panel_logo_1.grid(row=9,sticky=S, pady=(10, 0))

        credential_list = getAll("credentials_saved", "credentials")

        aux_str,usable_ids = createIdsAndStringSpecialCase(credential_list)
        reloadOptionMenu(credentialSelection, credential_menu, usable_ids)
        reloadOptionMenu(presentationSelection, presentation_menu, usable_ids)

        root.mainloop()

    def syncCredentials(self):
        global memory_credential_list
        global Credential_list, credentialSelection, credential_menu
        global ClientRSAkeyPair


        decryptor = PKCS1_OAEP.new(ClientRSAkeyPair,hashAlgo=SHA256 ,label="Encrypted with Public RSA key".encode('utf8'))
        
        avaliableCredentials_json = rpcCall("pendingCredentials")
        get_credentials_list = avaliableCredentials_json["result"]["credentials"]
        
        for i in range (0, len(get_credentials_list)):
            getCred_json = json.loads(get_credentials_list[i])
            if getCred_json["Credential"]["lock key"]["encrypted"]:
                lock_key_enc = getCred_json["Credential"]["lock key"]["value"]
                lock_key_enc_bytes = binascii.a2b_base64(lock_key_enc)
                lock_key_dec_bytes = decryptor.decrypt(lock_key_enc_bytes)
                getCred_json["Credential"]["lock key"]["value"] = lock_key_dec_bytes.decode("utf-8") 
                getCred_json["Credential"]["lock key"]["encrypted"] = False
                get_credentials_list[i] = getCred_json

        setMultiple("credentials_saved", "credentials", get_credentials_list)

        memory_credential_list = getAll("credentials_saved", "credentials")

        new_credential_list = avaliableCredentials_json["result"]["credentials"] # Lista descargada

        aux_str,_ = createIdsAndStringSpecialCase(new_credential_list)
        
        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            _,usable_ids = createIdsAndStringSpecialCase(memory_credential_list)
            reloadOptionMenu(credentialSelection, credential_menu, usable_ids)
            reloadOptionMenu(presentationSelection, presentation_menu, usable_ids)
            aux_str = "Credentials syncronized"

        mbox.showinfo("Result", aux_str)

    def check_cred_info(self):
        global credentialSelection
        global memory_credential_list

        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        parsed = memory_credential_list[position]

        RSA_key = parsed["Subject Public key"]
        RSA_key_Shortened = RSA_key[:40] + "...." + RSA_key[-40:]
        parsed["Subject Public key"] = RSA_key_Shortened

        issuer_signature = parsed["IssuerSignature"]
        issuer_signature_short = issuer_signature[:8] + "...." + issuer_signature[-8:]
        parsed["IssuerSignature"] = issuer_signature_short


        mbox.showinfo("Result", json.dumps(parsed, indent=4))
        
    def askNewCredential(self):
        global credTypesSelection

        pendingRequests_json = rpcCall("credentialRequest", {"name": "Alice", "type": credTypesSelection.get(), "DID": "1234"})
        print(pendingRequests_json)

        mbox.showinfo("Result", "Credential request sent")

    def sendToServiceProvider(self):
        global presentationSelection

        credential_list = getAll("credentials_saved", "credentials")

        presentationPosition = presentationSelection.get()
        position = int(presentationPosition.split(':')[0])
        parsed = credential_list[position]

        pendingRequests_json = rpcCall("presentation", parsed)

        mbox.showinfo("Result", "Presentation sent to Service Provider")


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
