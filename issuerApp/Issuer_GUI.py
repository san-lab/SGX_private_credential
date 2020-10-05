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

import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, popOne, getOne
from utilities.GUI_Utilities import reloadOptionMenu, createIdsAndString
from utilities.communicationToRPC import rpcCall, apiCall
from utilities.cryptoOps import calculateSymKey, getCompressedPubFromPriv, getPackedPubFromPriv, calulateUnlockAndMaskedUnlock, createKeyPair, calculateDiffieHash, getS, test
from utilities.assetUnlock import settlePayKeyInvoice, checkBalance

class App():
    def __init__(self):
        global root
        global Credential_list, credentialSelection, credential_menu
        global Request_list, requestSelection, request_menu
        global Response_list, responseSelection, response_menu
        global Lock_key_list, lock_key_Selection, lock_key_menu
        global Payment_list, payment_Selection, payment_menu
        global bankPrivateECKey, compressedPublicECKey, packedPublicECKey

        root = Tk()
        root.geometry('330x600')
        root.configure(bg='red2')
        root.title('Issuer credential app')

        bankPrivateECKey = 8922796882388619604127911146068705796569681654940873967836428543013949233636
        compressedPublicECKey = getCompressedPubFromPriv(bankPrivateECKey)
        packedPublicECKey = getPackedPubFromPriv(bankPrivateECKey)

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

        Payment_list = [
        ""
        ]

        self.button("Retrieve credential request", 1, self.requestRetrieve)
        requestSelection, request_menu = self.multipleSelect(Request_list, 2)
        self.button("Generate credential", 3, self.generateCredential)
        credentialSelection, credential_menu = self.multipleSelect(Credential_list, 4)
        self.button("Encrypt credential on SGX", 5, self.encryptOnSgx)
        responseSelection, response_menu = self.multipleSelect(Response_list, 6)
        self.button("Send credential to customer", 7, self.sendCredential)
        self.button("Retrieve unlock request", 8, self.retrieveLockKeys)
        lock_key_Selection, lock_key_menu = self.multipleSelect(Lock_key_list, 9)
        self.button("Send key invoice", 10, self.sendInvoice)
        self.button("Retrieve key payments", 11, self.retrievePayments)
        payment_Selection, payment_menu = self.multipleSelect(Payment_list, 12)
        self.button("Claim payment and commit key", 13, self.settlePaymentAndCommitKey)
        self.button("Check balance", 14, self.checkBalance)

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

        list_payment = getAll("payments_issuer", "payments")
        
        _, usable_ids = createIdsAndString(list_payment, False, "invoiceNumber", "challenge", " for ")
        reloadOptionMenu(payment_Selection, payment_menu, usable_ids)

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

        mbox.showinfo("Result", "Pending requests retrieved")

    def generateCredential(self):
        global plain_credential_list
        global Credential_list, credentialSelection, credential_menu
        global Request_list, requestSelection, request_menu

        requestPosition = requestSelection.get()
        position = int(requestPosition.split(':')[0])

        credential_request = json.dumps(popOne("credentials_request", "request", position))
        list_waiting_req_memory = getAll("credentials_request", "request")

        _, usable_ids_req = createIdsAndString(list_waiting_req_memory, False, "type", "name", " for ")
        reloadOptionMenu(requestSelection, request_menu, usable_ids_req)

        res_json = apiCall("issue3", credential_request)

        res_str = json.dumps(res_json)

        setOne("credentials_issuer", "plain_credentials", res_str)
        plain_credential_list = getAll("credentials_issuer", "plain_credentials")

        aux_str, usable_ids = createIdsAndString(plain_credential_list, True, "Type", "Name", " for ", subName="Credential")
        
        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            reloadOptionMenu(credentialSelection, credential_menu, usable_ids)
            aux_str = "Credential generated"

        RSA_key = res_json["Subject Public key"]
        RSA_key_Shortened = RSA_key[:40] + "...." + RSA_key[-40:]
        res_json["Subject Public key"] = RSA_key_Shortened

        mbox.showinfo("Result", json.dumps(res_json, indent=4))

    def encryptOnSgx(self):
        global Response_list, responseSelection, response_menu
        global Credential_list, credentialSelection, credential_menu

        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        data = popOne("credentials_issuer", "plain_credentials", position)
        data_json = json.loads(data)
        data_json["Issuer public key"] = packedPublicECKey
        data = json.dumps(data_json)
        plain_credential_list = getAll("credentials_issuer" ,"plain_credentials")
        req_json = apiCall("encryptbn256", data)
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

        RSA_key = req_json["Subject Public key"]
        RSA_key_Shortened = RSA_key[:40] + "...." + RSA_key[-40:]
        req_json["Subject Public key"] = RSA_key_Shortened

        lock_key = req_json["Credential"]["lock key"]["value"]
        lock_key_shortened = lock_key[:8] + "...." + lock_key[-8:]
        req_json["Credential"]["lock key"]["value"] = lock_key_shortened

        issuer_signature = req_json["IssuerSignature"]
        issuer_signature_short = issuer_signature[:8] + "...." + issuer_signature[-8:]
        req_json["IssuerSignature"] = issuer_signature_short

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
        global lock_key_Selection, lock_key_menu

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

        mbox.showinfo("Result", "Unlock keys requests retrieved")

    def sendInvoice(self):
        # Calculate t, T

        lock_keyPosition = lock_key_Selection.get()
        position = int(lock_keyPosition.split(':')[0]) #TODO fix this

        lock_key_json = getOne("lock_keys_issuer", "lock_keys", position)

        lock_key_packed = lock_key_json["key"]
        unlockKey, TUnlockKey = calulateUnlockAndMaskedUnlock(bankPrivateECKey, lock_key_packed)

        print(unlockKey, TUnlockKey)
        keyPair = createKeyPair()

        diffieHash = calculateDiffieHash(keyPair[0], lock_key_json["ephKeyX"], lock_key_json["ephKeyY"])

        newInvoice = {"DID":"125", "invoiceNumber": "456", "masked_unlock_keyX": TUnlockKey.x, "masked_unlock_keyY": TUnlockKey.y, "ephKeyX": keyPair[1], "ephKeyY": keyPair[2]}
        rpcCall("invoice", newInvoice)
        setOne("payments_issuer", "invoices", newInvoice)
        setOne("payments_issuer", "unlock_keys", {"unlockKey": unlockKey, "diffieHash": diffieHash})

        mbox.showinfo("Result", "Invoice sent. Number: 456")

    def retrievePayments(self):
        global payment_Selection, payment_menu

        payments_json = rpcCall("pendingPayments")
        setMultiple("payments_issuer", "payments", payments_json["result"]["payments"])

        list_waiting_payments = payments_json["result"]["payments"]
        complete_list_payments = getAll("payments_issuer", "payments")

        aux_str, _ = createIdsAndString(list_waiting_payments, False, "challenge", "DID", " for ")
        if aux_str == "":
            aux_str = "No requests pending"

        else:
            _, usable_ids = createIdsAndString(complete_list_payments, False, "challenge", "DID", " for ")
            reloadOptionMenu(payment_Selection, payment_menu, usable_ids)
            aux_str = "Payments retrieved"

        mbox.showinfo("Result", aux_str)

    def checkBalance(self):
        balance = checkBalance()
        mbox.showinfo("Result", "Your balance is " + str(balance))

    def settlePaymentAndCommitKey(self):
        global Payment_list, payment_Selection, payment_menu

        payment_Position = payment_Selection.get()
        position = int(payment_Position.split(':')[0])

        ########
        payment_json2 = getOne("payments_issuer", "payments", position)
        payment_json = getOne("payments_issuer", "unlock_keys", position)
        test(payment_json["unlockKey"], payment_json["diffieHash"],payment_json2["challenge"])

        s = getS(payment_json["unlockKey"], payment_json["diffieHash"])
        print(s)
        #########
        settlePayKeyInvoice(s)
        rpcCall("challenge", payment_json2["challenge"])

        mbox.showinfo("Result", "Payment settled")

def main():
    App()

    return 0


if __name__ == '__main__':
    main()
