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

import base64
import binascii
import json
import os
import sys
import time
import uuid
from datetime import datetime
from tkinter import *
from tkinter import _setit
from tkinter import messagebox as mbox
from tkinter import ttk
from tkinter.filedialog import askopenfilename, asksaveasfilename

import Padding
import requests
from dotenv import load_dotenv
from PIL import Image, ImageTk

sys.path.append('../')
from dao.dao import getAll, getOne, popOne, setMultiple, setOne
from utilities.communicationToRPC import apiCall, rpcCall
from utilities.cryptoOps import createKeyPair, decrypt, verify, calculateChallenge
from utilities.GUI_Utilities import (createIdsAndString,
                                     createIdsAndStringSpecialCase,
                                     reloadOptionMenu)
from utilities.assetUnlock import payKeyInvoice


class App():
    def __init__(self):
        global root
        global Presentation_List, presentationSelection, presentation_menu
        global PreWithKey_list, preWithKeySelection, preWithKey_menu
        global KeyInvoice_list, keyInvoiceSelection, keyInvoice_menu
        global Plain_list, plainSelection, plain_menu
        global cv, g,p,q

        root = Tk()
        root.geometry('330x600')
        root.configure(bg='green')
        root.title('Bankia app')

        Presentation_list = [
        ""
        ]

        KeyInvoice_list = [
        ""
        ]

        PreWithKey_list = [
        ""
        ]

        Plain_list = [
        ""
        ]

        self.button("Retrieve user presentations", 1, self.retrieveUserCredentials)
        presentationSelection, presentation_menu = self.multipleSelect(Presentation_list, 2)
        self.button("View encrypted presentation info", 3, self.checkInfoEnc)
        self.button("Ask for unlock key", 4, self.askUnlockKey)
        self.button("Retrieve key invoices", 5, self.retrieveKeyInvoices)
        keyInvoiceSelection, keyInvoice_menu = self.multipleSelect(KeyInvoice_list, 6)
        self.button("Pay key invoice", 7, self.payInvoice)
        self.button("Retrieve pending unlock keys", 8, self.retrievePendingUnlock)       
        preWithKeySelection, preWithKey_menu = self.multipleSelect(PreWithKey_list, 9)
        self.button("Decrypt presentation", 10, self.decryptPresent) 
        plainSelection, plain_menu = self.multipleSelect(Plain_list, 11)
        self.button("View plain presentation info", 12, self.checkInfoPlain) 
        self.button("Validate signature", 13, self.validateSignature)

        self.loadLists("credentials_serviceP", "encrypted_credentials", None, presentationSelection, presentation_menu)

        key_invoice_requests = getAll("invoices_serviceP", "invoices")
        
        _, usable_ids = createIdsAndString(key_invoice_requests, False, "invoiceNumber", "DID", " for ")
        reloadOptionMenu(keyInvoiceSelection, keyInvoice_menu, usable_ids)

        self.loadLists("credentials_serviceP", "encrypted_credentials_withK", "(with key)", preWithKeySelection, preWithKey_menu)
        self.loadLists("credentials_serviceP", "plain_credentials", "(decrypted)", plainSelection, plain_menu)
        root.mainloop()

    def button(self, bText, bRow, bFunc):
        b = ttk.Button(
            root, text=bText,
            command=bFunc)
        b.grid(row=bRow, sticky='ew', pady=(11, 7), padx=(25, 0))

    def multipleSelect(self, sList, sRow):
        selection = StringVar(root)
        selection.set(sList[0]) # default value
        menu = OptionMenu(root, selection, *sList)
        menu.grid(row=sRow, sticky='ew', pady=(11, 7), padx=(25, 0))
        return selection, menu

    def loadLists(self, fileName, subName, sEndingLabel, selection, menu):
        tempList = getAll(fileName, subName)
        _, usable_ids = createIdsAndString(tempList, False, "Type", "Name", " for ", subName="Credential", endingLabel=sEndingLabel)
        reloadOptionMenu(selection, menu, usable_ids)



    def retrieveUserCredentials(self):
        global Presentation_List, presentationSelection, presentation_menu

        presentations_json = rpcCall("pendingPresentations")
        print(presentations_json)

        setMultiple("credentials_serviceP", "encrypted_credentials", presentations_json["result"]["presentations"]) 

        list_waiting_presentations = presentations_json["result"]["presentations"]
        complete_list_presentations = getAll("credentials_serviceP", "encrypted_credentials")

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

        keyPair = createKeyPair()
        setOne("invoices_serviceP", "ephPrivKeys", keyPair[0])
        rpcCall("lockKey", {"DID": "4567", "key": enc_credential["Credential"]["lock key"]["value"], "ephKeyX": keyPair[1], "ephKeyY": keyPair[2]})

        mbox.showinfo("Result", "Unlock key request sent")

    def retrieveKeyInvoices(self):
        invoices_json = rpcCall("pendingInvoices")


        setMultiple("invoices_serviceP", "invoices", invoices_json["result"]["invoices"]) 

        complete_list_invoices = getAll("invoices_serviceP", "invoices")

        _, usable_ids = createIdsAndString(complete_list_invoices, False, "invoiceNumber", "DID", " for ")
        reloadOptionMenu(keyInvoiceSelection, keyInvoice_menu, usable_ids)

        print(invoices_json)

        mbox.showinfo("Result", "Invoices retrieved")

    def payInvoice(self):

        invoicePosition = keyInvoiceSelection.get()
        position = int(invoicePosition.split(':')[0])

        invoice_list = getAll("invoices_serviceP", "invoices")

        parsed = invoice_list[position]
        ephPrivK = getOne("invoices_serviceP", "ephPrivKeys", position)
        challenge = calculateChallenge(ephPrivK, parsed["ephKeyX"], parsed["ephKeyY"], parsed["masked_unlock_keyX"], parsed["masked_unlock_keyY"])

        payKeyInvoice(challenge)
        rpcCall("payment", {"DID": "4567", "invoiceNumber": parsed["invoiceNumber"], "challenge": challenge})

        mbox.showinfo("Result", "Invoice payed:" + json.dumps(parsed, indent=4))

    def retrievePendingUnlock(self):
        global PreWithKey_list, preWithKeySelection, preWithKey_menu

        challenge_json = rpcCall("pendingChallenges")
        print(challenge_json)
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
        plain_bytes = decrypt(key_bytes, cipher_bytes)
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

        plainKPosition = plainSelection.get()
        position = int(plainKPosition.split(':')[0])

        plain_credential = getOne("credentials_serviceP", "plain_credentials", position)

        issuer_pubK_comp = plain_credential["Issuer public key"]
        issuer_signature = plain_credential["IssuerSignature"]
        message = plain_credential["Credential"]["Name"] + plain_credential["Credential"]["DID"] + plain_credential["Credential"]["Type"] + plain_credential["Credential"]["value"] + plain_credential["IssuerDID"]

        valid = verify(message,issuer_pubK_comp,issuer_signature)
        print(valid)
        if valid:
            mbox.showinfo("Result", "The signature is valid")
        else:
            mbox.showinfo("Result", "The signature is not valid")


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
