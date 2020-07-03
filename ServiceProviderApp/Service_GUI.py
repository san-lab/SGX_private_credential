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
from dao.dao import getAll, setOne, setMultiple
from utilities.GUI_Utilities import reloadOptionMenu, createIdsAndString, createIdsAndStringSpecialCase



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

        _, usable_ids = createIdsAndString(enc_credentia_withK_list, False, "Type", "Name", " for ", subName="Credential")
        reloadOptionMenu(preWithKeySelection, preWithKey_menu, usable_ids)

        plain_credential_list = getAll("credentials_serviceP", "plain_credentials")

        _, usable_ids = createIdsAndString(plain_credential_list, False, "Type", "Name", " for ", subName="Credential", endingLabel="(encrypted)")
        reloadOptionMenu(plainSelection, plain_menu, usable_ids)

        root.mainloop()

    def retrieveUserCredentials(self):
        print("Retrieve credentials")

    def checkInfoEnc(self):
        global presentationSelection

        credentialPosition = presentationSelection.get()
        position = int(credentialPosition.split(':')[0])

        enc_credential_list = getAll("credentials_serviceP", "encrypted_credentials")

        parsed = enc_credential_list[position]
        mbox.showinfo("Result", json.dumps(parsed, indent=4))

    def askUnlockKey(self):
        print("askUnlock")

    def retrievePendingUnlock(self):
        print("Retrieve pending unlock")

    def decryptPresent(self):
        print("decryptPresentation")

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
