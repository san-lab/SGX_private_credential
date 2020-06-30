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



class App():
    def __init__(self):
        global root
        global Credential_list, credentialSelection, credential_menu
        global e0, e1, e2

        root = Tk()
        root.geometry('300x500')

        root.configure(bg='red2')
        root.title('User credential wallet')

        Credential_list = [
        ""
        ]

        credentialType_list = [
        "Good payer cert",
        "Credit scoring",
        "Bank account number"
        ]

        b1 = ttk.Button(
            root, text="Download pending credentials",
            command=self.downloadPending)
        b1.grid(row=1, sticky='ew', pady=(11, 7), padx=(25, 0))

        b1 = ttk.Button(
            root, text="List all credentials",
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

        e0 = ttk.Entry(root)
        e0.grid(row=5,  pady=(11, 7))
        e0.insert(0,"Name")

        e1 = StringVar(root)
        e1.set(credentialType_list[0]) # default value

        credTypes_menu = OptionMenu(root, e1, *credentialType_list)
        #credential_menu.pack()
        credTypes_menu.grid(row=6, sticky='ew', pady=(11, 7), padx=(25, 0))

        e2 = ttk.Entry(root)
        e2.grid(row=7,  pady=(11, 7))
        e2.insert(0,"DID")

        b3 = ttk.Button(
            root, text="      Ask for a new credential      ",
            command=self.askNewCredential)
        b3.grid(row=8, sticky='ew', pady=(11, 7), padx=(25, 0))


        img_logo = ImageTk.PhotoImage(Image.open(
            "./images/santander-logo-13.png"))
        panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        panel_logo_1.grid(row=9,sticky=S, pady=(10, 0))

        credentials_file = open("./credentials_saved.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credential_list = credentials_json["credentials"]

        aux_str = ""
        usable_ids = list()
        for i in range (0,len(credential_list)):
            #cred_json = credential_list[i]
            cred = credential_list[i]
            cred_json = json.loads(cred)
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

    def downloadPending(self):
        print("Download")

    def showListCredentials(self):
        global credential_list
        global Credential_list, credentialSelection, credential_menu

        credentials_file = open("./credentials_saved.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credential_list = credentials_json["credentials"]

        #data = {
        #    "jsonrpc": "2.0",
        #    "method": "pendingCredentials",
        #    "id": 1,
        #    "params": []
        #}
        #avaliableCredentials = requests.post('http://localhost:3000/jsonrpc' , data=json.dumps(data))
        #avaliableCredentials_json = avaliableCredentials.json()

        #print(avaliableCredentials_json["result"]["credentials"])
        #credential_list = avaliableCredentials_json["result"]["credentials"]

        aux_str = ""
        usable_ids = list()
        for i in range (0,len(credential_list)):
            #cred_json = credential_list[i]
            cred = credential_list[i]
            cred_json = json.loads(cred)
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

        mbox.showinfo("Result", aux_str)

    def check_cred_info(self):
        global credentialSelection
        global credential_list

        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        parsed = json.loads(credential_list[position])
        print(parsed)
        mbox.showinfo("Result", json.dumps(parsed, indent=4))
        
    def askNewCredential(self):
        global e0, e1, e2

        data = {
            "jsonrpc": "2.0",
            "method": "credentialRequest",
            "id": 1,
            "params": [{"name": e0.get(), "type": e1.get(), "DID": e2.get()}]
        }
        pendingRequests = requests.post('http://localhost:3000/jsonrpc' , data=json.dumps(data))
        pendingRequests_json = pendingRequests.json()
        print(pendingRequests_json)


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
