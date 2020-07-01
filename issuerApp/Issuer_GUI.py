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
        global Request_list, requestSelection, request_menu
        global Response_list, responseSelection, response_menu

        root = Tk()
        root.geometry('300x500')

        root.configure(bg='red2')
        root.title('Issuer credential app')

        Credential_list = [
        ""
        ]

        Request_list = [
        ""
        ]

        Response_list = [
        ""
        ]


        b0 = ttk.Button(
            root, text="Retrieve credential request",
            command=self.requestRetrieve)
        b0.grid(row=1, sticky='ew', pady=(11, 7), padx=(25, 0))

        requestSelection = StringVar(root)
        requestSelection.set(Request_list[0])  # default value

        request_menu = OptionMenu(root, requestSelection, *Request_list)
        request_menu.grid(row=2, sticky='ew', pady=(11, 7), padx=(25, 0))

        b1 = ttk.Button(
            root, text="Generate credential",
            command=self.generateCredential)
        b1.grid(row=3, sticky='ew', pady=(11, 7), padx=(25, 0))

        credentialSelection = StringVar(root)
        credentialSelection.set(Credential_list[0])  # default value

        credential_menu = OptionMenu(
            root, credentialSelection, *Credential_list)
        credential_menu.grid(row=4, sticky='ew', pady=(11, 7), padx=(25, 0))

        b2 = ttk.Button(
            root, text="Encrypt credential on SGX",
            command=self.encryptOnSgx)
        b2.grid(row=5, sticky='ew', pady=(11, 7), padx=(25, 0))

        responseSelection = StringVar(root)
        responseSelection.set(Response_list[0])  # default value

        response_menu = OptionMenu(
            root, responseSelection, *Response_list)
        response_menu.grid(row=6, sticky='ew', pady=(11, 7), padx=(25, 0))

        b3 = ttk.Button(
            root, text="      Send credential to customer     ",
            command=self.sendCredential)
        b3.grid(row=7, sticky='ew', pady=(11, 7), padx=(25, 0))

        img_logo = ImageTk.PhotoImage(Image.open(
            "./images/santander-logo-13.png"))
        panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        panel_logo_1.grid(row=8, sticky=S, pady=(10, 0))

        credentials_file = open("./credentials_issuer.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credentials_file.close()

        plain_credential_list = credentials_json["plain_credentials"]

        aux_str = ""
        usable_ids = list()
        for i in range(0, len(plain_credential_list)):
            cred = plain_credential_list[i]
            cred_json = json.loads(cred)
            new_id = str(i) + ": " + cred_json["Credential"]["Type"] + \
                         " for " + cred_json["Credential"]["Name"] + "\n"
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
                credential_menu['menu'].add_command(
                    label=_id, command=_setit(credentialSelection, _id))
                count = count+1


        credentials_file = open("./credentials_issuer.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credentials_file.close()

        enc_credential_list = credentials_json["encrypted_credentials"]

        aux_str = ""
        usable_ids = list()
        for i in range(0, len(enc_credential_list)):
            cred = enc_credential_list[i]
            cred_json = json.loads(cred)
            new_id = str(i) + ": " + cred_json["Credential"]["Type"] + \
                         " for " + cred_json["Credential"]["Name"] + "(encrypted)" + "\n"
            usable_ids.append(new_id)
            aux_str = aux_str + new_id + "\n"

        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            responseSelection.set('')
            response_menu['menu'].delete(0, 'end')

            # Insert list of new options (tk._setit hooks them up to var)
            count = 0
            for _id in usable_ids:
                response_menu['menu'].add_command(
                    label=_id, command=_setit(responseSelection, _id))
                count = count+1

        credential_request_file = open("./credentials_request.json", "r")
        credential_request_str = credential_request_file.read()
        credential_request_json = json.loads(credential_request_str)
        credential_request_file.close()

        list_waiting_requests = credential_request_json["request"]

        aux_str = ""
        usable_ids = list()
        for i in range(0, len(list_waiting_requests)):
            request_json = list_waiting_requests[i]
            new_id = str(
                i) + ": " + request_json["type"] + " for " + request_json["name"] + "\n"
            usable_ids.append(new_id)
            aux_str = aux_str + new_id + "\n"

        if aux_str == "":
            aux_str = "No requests pending"

        else:
            requestSelection.set('')
            request_menu['menu'].delete(0, 'end')

            # Insert list of new options (tk._setit hooks them up to var)
            count = 0
            for _id in usable_ids:
                request_menu['menu'].add_command(
                    label=_id, command=_setit(requestSelection, _id))
                count = count+1

        root.mainloop()

    def requestRetrieve(self):
        global list_waiting_req_memory
        global Request_list, requestSelection, request_menu
        data = {
            "jsonrpc": "2.0",
            "method": "pendingRequests",
            "id": 1,
            "params": []
        }
        pendingRequests = requests.post(
            'http://localhost:3000/jsonrpc', data=json.dumps(data))
        pendingRequests_json = pendingRequests.json()

        credential_request_file = open("./credentials_request.json", "r")
        credential_request_str = credential_request_file.read()
        credential_request_json = json.loads(credential_request_str)
        credential_request_file.close()

        credential_request_json["request"] += pendingRequests_json["result"]["request"]

        list_waiting_req_memory = credential_request_json["request"]

        print (credential_request_json)

        credential_request_file_write = open("./credentials_request.json", "w")
        credential_request_file_write.write(json.dumps(credential_request_json))
        credential_request_file_write.close()


        list_waiting_requests = pendingRequests_json["result"]["request"]

        aux_str = ""
        usable_ids = list()
        for i in range(0, len(list_waiting_requests)):
            request_json = list_waiting_requests[i]
            new_id = str(
                i) + ": " + request_json["type"] + " for " + request_json["name"] + "\n"
            usable_ids.append(new_id)
            aux_str = aux_str + new_id + "\n"

        if aux_str == "":
            aux_str = "No requests pending"

        else:
            requestSelection.set('')
            request_menu['menu'].delete(0, 'end')

            # Insert list of new options (tk._setit hooks them up to var)
            count = 0
            for _id in usable_ids:
                request_menu['menu'].add_command(
                    label=_id, command=_setit(requestSelection, _id))
                count = count+1

        mbox.showinfo("Result", aux_str)

    def generateCredential(self):
        global plain_credential_list
        global Credential_list, credentialSelection, credential_menu

        global list_waiting_req_memory

        requestPosition = requestSelection.get()
        position = int(requestPosition.split(':')[0])

        credential_request = json.dumps(list_waiting_req_memory[position])
        response = requests.get(
            'http://40.120.61.169:8080/issue', data=credential_request)
        res_json = response.json()
        res_json["Issuer name"] = "Banco Santander"

        res_str = json.dumps(res_json)

        credentials_file = open("./credentials_issuer.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credentials_file.close()

        plain_credential_list = credentials_json["plain_credentials"]
        plain_credential_list.append(res_str)
        credentials_json["plain_credentials"] = plain_credential_list

        credentials_file_write = open("./credentials_issuer.json", "w")
        credentials_file_write.write(json.dumps(credentials_json))
        credentials_file_write.close()

        aux_str = ""
        usable_ids = list()
        for i in range(0, len(plain_credential_list)):
            cred = plain_credential_list[i]
            cred_json = json.loads(cred)
            new_id = str(i) + ": " + cred_json["Credential"]["Type"] + \
                         " for " + cred_json["Credential"]["Name"] + "\n"
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
                credential_menu['menu'].add_command(
                    label=_id, command=_setit(credentialSelection, _id))
                count = count+1

        mbox.showinfo("Result", aux_str)

    def encryptOnSgx(self):
        global credentialSelection
        global plain_credential_list
        global Response_list, responseSelection, response_menu

        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        data = plain_credential_list[position]
        req = requests.get('http://40.120.61.169:8080/submit', data=data)
        req_json = req.json()
        req_str = json.dumps(req_json)

        credentials_file = open("./credentials_issuer.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credentials_file.close()

        enc_credential_list = credentials_json["encrypted_credentials"]
        enc_credential_list.append(req_str)
        credentials_json["encrypted_credentials"] = enc_credential_list

        credentials_file_write = open("./credentials_issuer.json", "w")
        credentials_file_write.write(json.dumps(credentials_json))
        credentials_file_write.close()

        aux_str = ""
        usable_ids = list()
        for i in range(0, len(enc_credential_list)):
            cred = enc_credential_list[i]
            cred_json = json.loads(cred)
            new_id = str(i) + ": " + cred_json["Credential"]["Type"] + \
                         " for " + cred_json["Credential"]["Name"] + "(encrypted)" + "\n"
            usable_ids.append(new_id)
            aux_str = aux_str + new_id + "\n"

        if aux_str == "":
            aux_str = "No credentials loaded"

        else:
            responseSelection.set('')
            response_menu['menu'].delete(0, 'end')

            # Insert list of new options (tk._setit hooks them up to var)
            count = 0
            for _id in usable_ids:
                response_menu['menu'].add_command(
                    label=_id, command=_setit(responseSelection, _id))
                count = count+1

        mbox.showinfo("Result", aux_str)


        # mbox.showinfo("Result", json.dumps(parsed, indent=4))

    def sendCredential(self):
        credentials_file = open("./credentials_issuer.json", "r")
        credentials_str = credentials_file.read()
        credentials_json = json.loads(credentials_str)
        credentials_file.close()

        enc_credential_0 = json.loads(credentials_json["encrypted_credentials"][0])
        print(enc_credential_0)
        data = {
            "jsonrpc": "2.0",
            "method": "credential",
            "id": 1,
            "params": [enc_credential_0]
        }
        pendingRequests = requests.post('http://localhost:3000/jsonrpc' , data=json.dumps(data))
        pendingRequests_json = pendingRequests.json()
        print(pendingRequests_json)


def main():
    App()

    return 0


if __name__ == '__main__':
    main()
