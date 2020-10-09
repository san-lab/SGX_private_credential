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
def syncCredentials(credentialSelection, credential_menu,presentationSelection, presentation_menu, ClientRSAkeyPair):
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
    return memory_credential_list

def check_cred_info(credentialSelection,memory_credential_list):

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

def askNewCredential(credTypesSelection):

    pendingRequests_json = rpcCall("credentialRequest", {"name": "Alice", "type": credTypesSelection.get(), "DID": "1234"})
    print(pendingRequests_json)

    mbox.showinfo("Result", "Credential request sent")

def sendToServiceProvider(presentationSelection):

    credential_list = getAll("credentials_saved", "credentials")

    presentationPosition = presentationSelection.get()
    position = int(presentationPosition.split(':')[0])
    parsed = credential_list[position]

    pendingRequests_json = rpcCall("presentation", parsed)

    mbox.showinfo("Result", "Presentation sent to Service Provider")