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
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey

import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, popOne, getOne
from utilities.GUI_Utilities import reloadOptionMenu, createIdsAndString
from utilities.communicationToRPC import rpcCall, apiCall

class App():
    def __init__(self):
        global root
        global Credential_list, credentialSelection, credential_menu
        global Request_list, requestSelection, request_menu
        global Response_list, responseSelection, response_menu
        global digEmbasy_list, digEmbasy_Selection, digEmbasy_menu
        global bankPrivateECKey, bankPublicECKey, compressedPublicECKey, cv
        global compressedPublicECKeyTemporal
        global SGX_req_json, SGX_req_workerRet

        root = Tk()
        root.geometry('330x540')

        root.configure(bg='red2')
        root.title('Issuer credential app')

        cv = Curve.get_curve("Ed25519")
        g = cv.generator
        p = cv.field
        q = cv.order
        bankPrivateECKey = 8922796882388619604127911146068705796569681654940873967836428543013949233636
        bankPublicECKey = cv.mul_point(bankPrivateECKey, g)
        compressedPublicECKey = cv.encode_point(bankPublicECKey).hex()

        bankPrivateECKeyTemporal = 8922796882388619604127911146068705796569681654940873967836428543013949233637
        bankPublicECKeyTemporal = cv.mul_point(bankPrivateECKeyTemporal, g)
        compressedPublicECKeyTemporal = cv.encode_point(bankPublicECKeyTemporal).hex()

        SGX_req_json = {
        "jsonrpc": "2.0", 
        "method": "WorkOrderSubmit", 
        "id": 11, 
        "params": {
            "responseTimeoutMSecs": 6000, 
            "payloadFormat": "JSON-RPC", 
            "resultUri": "resulturi", 
            "notifyUri": "notifyuri", 
            "workOrderId": "", 
            "workerId": "0b03616a46ea9cf574f3f8eedc93a62c691a60dbd3783427c0243bacfe5bba94", 
            "workloadId": "", 
            "requesterId": "0x3456", 
            "dataEncryptionAlgorithm": "AES-GCM-256", 
            "encryptedSessionKey": "", 
            "sessionKeyIv": "", 
            "requesterNonce": "", 
            "encryptedRequestHash": "", 
            "requesterSignature": "", 
            "inData": [
                {"index": 1, 
                "data": "", 
                "encryptedDataEncryptionKey": "", 
                "iv": ""}
            ]
            }
        }

        SGX_req_workerRet = {"jsonrpc": "2.0", "method": "WorkerRetrieve", "id": 2, "params": {"workerId": "0b03616a46ea9cf574f3f8eedc93a62c691a60dbd3783427c0243bacfe5bba94"}}



        Credential_list = [
        ""
        ]

        Request_list = [
        ""
        ]

        Response_list = [
        ""
        ]

        digEmbasy_list = [
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

        digEmbasy_Selection = StringVar(root)
        digEmbasy_Selection.set(digEmbasy_list[0])  # default value

        digEmbasy_menu = OptionMenu(
            root, digEmbasy_Selection, *digEmbasy_list)
        digEmbasy_menu.grid(row=8, sticky='ew', pady=(11, 7), padx=(25, 0))

        b4 = ttk.Button(
            root, text="Set new key on digital embasy",
            command=self.updateEmbassyKey)
        b4.grid(row=9, sticky='ew', pady=(11, 7), padx=(25, 0))

        b4 = ttk.Button(
            root, text="Get balance on embassy",
            command=self.getBalance)
        b4.grid(row=10, sticky='ew', pady=(11, 7), padx=(25, 0))

        img_logo = ImageTk.PhotoImage(Image.open(
            "./images/santander-logo-13.png"))
        panel_logo_1 = Label(root, image=img_logo, borderwidth=0)
        panel_logo_1.grid(row=11, sticky=S, pady=(10, 0))


        plain_credential_list = getAll("credentials_issuer", "plain_credentials")

        _, usable_ids = createIdsAndString(plain_credential_list, True, "Type", "Name", " for ", subName="Credential")
        reloadOptionMenu(credentialSelection, credential_menu, usable_ids)

        enc_credential_list = getAll("credentials_issuer", "encrypted_credentials")

        _, usable_ids = createIdsAndString(enc_credential_list, True, "Type", "Name", " for ", subName="Credential", endingLabel="(encrypted)")
        reloadOptionMenu(responseSelection, response_menu, usable_ids)

        list_waiting_requests = getAll("credentials_request", "request")
        
        _, usable_ids = createIdsAndString(list_waiting_requests, False, "type", "name", " for ")
        reloadOptionMenu(requestSelection, request_menu, usable_ids)

        list_digitalEmbassys = getAll("digital_Embassys", "digEmbassysInfo")
        
        reloadOptionMenu(digEmbasy_Selection, digEmbasy_menu, list_digitalEmbassys)

        root.mainloop()

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
        global compressedPublicECKey

        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        data = popOne("credentials_issuer", "plain_credentials", position)
        data_json = json.loads(data)
        data_json["Issuer public key"] = compressedPublicECKey
        data = json.dumps(data_json)
        plain_credential_list = getAll("credentials_issuer" ,"plain_credentials")
        req_json = res_json = apiCall("submit3", data)
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

    def updateEmbassyKey(self): #TODO change key by bankPrivateECKeyTemporal
        global digEmbasy_list, digEmbasy_Selection, digEmbasy_menu

        embassyPosition = digEmbasy_Selection.get()
        position = int(embassyPosition.split(':')[0])

        embassyInfo = popOne("digital_Embassys", "digEmbassysInfo", position)
        name = embassyInfo["Name"]

        SGX_worker_info = apiCallSgxHard(SGX_req_workerRet)

        temp_SGX_json = SGX_req_json
        workloadId = "heart-disease-eval"
        workOrderId = "0x" + uuid.uuid4().hex[:16]
        temp_SGX_json["params"]["workOrderId"] = workOrderId
        temp_SGX_json["params"]["workloadId"] = workloadId.encode("UTF-8").hex()
        #temp_SGX_json["params"]["inData"][0]["data"] = "key:" + enc_credential["Credential"]["lock key"]["value"]
        temp_SGX_json["params"]["inData"][0]["data"] = "updateKey:"+bankPrivateECKeyTemporal
        SGX_json_enc, enc_session_json = encryptSGXWorkOrder(temp_SGX_json, SGX_worker_info)
        SGX_response = apiCallSgxHard(json.loads(SGX_json_enc))

        print("Response update digital embassy")
        print(SGX_response)

    def getBalance(self):
        print("TODO Balance")

def main():
    App()

    return 0


if __name__ == '__main__':
    main()
