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

from tkinter import messagebox as mbox

import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, popOne, getOne
from utilities.communicationToRPC import rpcCall, apiCall
from utilities.cryptoOps import calculateSymKey, getCompressedPubFromPriv, getPackedPubFromPriv, calulateUnlockAndMaskedUnlock, createKeyPair, calculateDiffieHash, getS, test
from utilities.assetUnlock import settlePayKeyInvoice, checkBalance
from utilities.GUI_Utilities import (createIdsAndString,
                                     reloadOptionMenu,
                                     button,
                                     multipleSelect,
                                     loadLists)
import IssuerLogic

class App():
    def __init__(self):
        global root
        global credentialSelection, credential_menu
        global requestSelection, request_menu
        global responseSelection, response_menu
        global lock_key_Selection, lock_key_menu
        global payment_Selection, payment_menu
        global bankPrivateECKey, compressedPublicECKey

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

        button(root, "Retrieve credential request", 1, self.requestRetrieve)
        requestSelection, request_menu = multipleSelect(root, Request_list, 2)
        button(root, "Generate credential", 3, self.generateCredential)
        credentialSelection, credential_menu = multipleSelect(root, Credential_list, 4)
        button(root, "Encrypt credential on SGX", 5, self.encryptOnSgx)
        responseSelection, response_menu = multipleSelect(root, Response_list, 6)
        button(root, "Send credential to customer", 7, self.sendCredential)
        button(root, "Retrieve unlock request", 8, self.retrieveLockKeys)
        lock_key_Selection, lock_key_menu = multipleSelect(root, Lock_key_list, 9)
        button(root, "Send key invoice", 10, self.sendInvoice)
        button(root, "Retrieve key payments", 11, self.retrievePayments)
        payment_Selection, payment_menu = multipleSelect(root, Payment_list, 12)
        button(root, "Claim payment and commit key", 13, self.settlePaymentAndCommitKey)
        button(root, "Check balance", 14, self.checkBalance)

        loadLists("credentials_issuer", "plain_credentials", None, credentialSelection, credential_menu)
        loadLists("credentials_issuer", "encrypted_credentials", "(encrypted)", responseSelection, response_menu)

        list_waiting_requests = getAll("credentials_request", "request")
        
        _, usable_ids = createIdsAndString(list_waiting_requests, "type", "name", " for ")
        reloadOptionMenu(requestSelection, request_menu, usable_ids)

        list_waiting_lock_keys = getAll("lock_keys_issuer", "lock_keys")
        
        _, usable_ids = createIdsAndString(list_waiting_lock_keys, "key", "DID", " for ")
        reloadOptionMenu(lock_key_Selection, lock_key_menu, usable_ids)

        list_payment = getAll("payments_issuer", "payments")
        
        _, usable_ids = createIdsAndString(list_payment, "invoiceNumber", "challenge", " for ")
        reloadOptionMenu(payment_Selection, payment_menu, usable_ids)

        root.mainloop()

    def requestRetrieve(self):
        global requestSelection, request_menu
        IssuerLogic.requestRetrieve(requestSelection, request_menu)

    def generateCredential(self):
        global plain_credential_list
        global credentialSelection, credential_menu
        global requestSelection, request_menu
        plain_credential_list = IssuerLogic.generateCredential(credentialSelection, credential_menu,requestSelection, request_menu)

    def encryptOnSgx(self):
        global responseSelection, response_menu
        global credentialSelection, credential_menu
        global compressedPublicECKey
        IssuerLogic.encryptOnSgx(responseSelection, response_menu,credentialSelection, credential_menu, compressedPublicECKey)

    def sendCredential(self):
        global responseSelection, response_menu
        IssuerLogic.sendCredential(responseSelection, response_menu)

    def retrieveLockKeys(self):
        global lock_key_Selection, lock_key_menu
        IssuerLogic.retrieveLockKeys(lock_key_Selection, lock_key_menu)

    def sendInvoice(self):
        global lock_key_Selection
        global bankPrivateECKey
        IssuerLogic.sendInvoice(lock_key_Selection,bankPrivateECKey)

    def retrievePayments(self):
        global payment_Selection, payment_menu
        IssuerLogic.retrievePayments(payment_Selection, payment_menu)

    def checkBalance(self):
        IssuerLogic.checkBalance()

    def settlePaymentAndCommitKey(self):
        global payment_Selection
        IssuerLogic.settlePaymentAndCommitKey(payment_Selection)

def main():
    App()

    return 0


if __name__ == '__main__':
    main()
