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

import sys
from tkinter import *
from tkinter import ttk

import Padding
from PIL import Image, ImageTk

sys.path.append('../')
from dao.dao import getAll
from utilities.communicationToRPC import apiCall, rpcCall
from utilities.GUI_Utilities import (createIdsAndString,
                                     createIdsAndStringSpecialCase,
                                     reloadOptionMenu,
                                     button,
                                     multipleSelect,
                                     loadLists)
import ServiceLogic

class App():
    def __init__(self):
        global root
        global presentationSelection, presentation_menu
        global preWithKeySelection, preWithKey_menu
        global keyInvoiceSelection, keyInvoice_menu
        global plainSelection, plain_menu
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

        button(root, "Retrieve user presentations", 1, self.retrieveUserCredentials)
        presentationSelection, presentation_menu = multipleSelect(root, Presentation_list, 2)
        button(root, "View encrypted presentation info", 3, self.checkInfoEnc)
        button(root, "Ask for unlock key", 4, self.askUnlockKey)
        button(root, "Retrieve key invoices", 5, self.retrieveKeyInvoices)
        keyInvoiceSelection, keyInvoice_menu = multipleSelect(root, KeyInvoice_list, 6)
        button(root, "Pay key invoice", 7, self.payInvoice)
        button(root, "Retrieve pending unlock keys", 8, self.retrievePendingUnlock)       
        preWithKeySelection, preWithKey_menu = multipleSelect(root, PreWithKey_list, 9)
        button(root, "Decrypt presentation", 10, self.decryptPresent) 
        plainSelection, plain_menu = multipleSelect(root, Plain_list, 11)
        button(root, "View plain presentation info", 12, self.checkInfoPlain) 
        button(root, "Validate signature", 13, self.validateSignature)

        loadLists("credentials_serviceP", "encrypted_credentials", None, presentationSelection, presentation_menu)

        key_invoice_requests = getAll("invoices_serviceP", "invoices")
        
        _, usable_ids = createIdsAndString(key_invoice_requests, "invoiceNumber", "DID", " for ")
        reloadOptionMenu(keyInvoiceSelection, keyInvoice_menu, usable_ids)

        loadLists("credentials_serviceP", "encrypted_credentials_withK", "(with key)", preWithKeySelection, preWithKey_menu)
        loadLists("credentials_serviceP", "plain_credentials", "(decrypted)", plainSelection, plain_menu)
        root.mainloop()

    def retrieveUserCredentials(self):
        global presentationSelection, presentation_menu
        ServiceLogic.retrieveUserCredentials(presentationSelection, presentation_menu)

    def checkInfoEnc(self):
        global presentationSelection
        ServiceLogic.checkInfoEnc(presentationSelection)

    def askUnlockKey(self):
        global presentationSelection, presentation_menu
        ServiceLogic.askUnlockKey(presentationSelection, presentation_menu)

    def retrieveKeyInvoices(self):
        global keyInvoiceSelection, keyInvoice_menu
        ServiceLogic.retrieveKeyInvoices(keyInvoiceSelection, keyInvoice_menu)

    def payInvoice(self):
        global keyInvoiceSelection
        ServiceLogic.payInvoice(keyInvoiceSelection)

    def retrievePendingUnlock(self):
        global preWithKeySelection, preWithKey_menu
        ServiceLogic.retrievePendingUnlock(preWithKeySelection, preWithKey_menu)

    def decryptPresent(self):
        global preWithKeySelection, preWithKey_menu
        global plainSelection, plain_menu
        ServiceLogic.decryptPresent(preWithKeySelection, preWithKey_menu,plainSelection, plain_menu)

    def checkInfoPlain(self):
        global plainSelection
        ServiceLogic.checkInfoPlain(plainSelection)

    def validateSignature(self):
        global plainSelection, plain_menu
        ServiceLogic.validateSignature(plainSelection, plain_menu)


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
