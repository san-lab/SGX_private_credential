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
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

import os
import UserLogic
import sys
sys.path.append('../')
from dao.dao import getAll
from utilities.GUI_Utilities import (createIdsAndStringSpecialCase,
                                     reloadOptionMenu,
                                     button,
                                     multipleSelect,
                                     loadLists)


class App():
    def __init__(self):
        global credentialSelection, credential_menu
        global presentationSelection, presentation_menu
        global credTypesSelection
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
        global credentialSelection, credential_menu
        global presentationSelection, presentation_menu
        global ClientRSAkeyPair
        memory_credential_list = UserLogic.syncCredentials(credentialSelection, credential_menu,presentationSelection, presentation_menu, ClientRSAkeyPair)

    def check_cred_info(self):
        global credentialSelection
        global memory_credential_list
        UserLogic.check_cred_info(credentialSelection,memory_credential_list)
        
    def askNewCredential(self):
        global credTypesSelection
        UserLogic.askNewCredential(credTypesSelection)

    def sendToServiceProvider(self):
        global presentationSelection
        UserLogic.sendToServiceProvider(presentationSelection)


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
