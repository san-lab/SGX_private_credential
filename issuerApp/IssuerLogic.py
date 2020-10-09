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

def requestRetrieve(requestSelection, request_menu):
    pendingRequests_json = rpcCall("pendingRequests")

    setMultiple("credentials_request", "request", pendingRequests_json["result"]["request"]) 

    list_waiting_requests = pendingRequests_json["result"]["request"]
    complete_list_requests = getAll("credentials_request", "request")

    aux_str, _ = createIdsAndString(list_waiting_requests, "type", "name", " for ")
    if aux_str == "":
        aux_str = "No requests pending"

    else:
        _, usable_ids = createIdsAndString(complete_list_requests, "type", "name", " for ")
        reloadOptionMenu(requestSelection, request_menu, usable_ids)

    mbox.showinfo("Result", "Pending requests retrieved")

def generateCredential(credentialSelection, credential_menu,requestSelection, request_menu):
    requestPosition = requestSelection.get()
    position = int(requestPosition.split(':')[0])

    credential_request = json.dumps(popOne("credentials_request", "request", position))
    list_waiting_req_memory = getAll("credentials_request", "request")

    _, usable_ids_req = createIdsAndString(list_waiting_req_memory, "type", "name", " for ")
    reloadOptionMenu(requestSelection, request_menu, usable_ids_req)

    res_json = apiCall("issue3", credential_request)
    print("ISSUER SIGNATURE BEFORE ENCRYPT")
    print(res_json["IssuerSignature"])

    res_str = json.dumps(res_json)

    setOne("credentials_issuer", "plain_credentials", res_str)
    plain_credential_list = getAll("credentials_issuer", "plain_credentials")

    aux_str, usable_ids = createIdsAndString(plain_credential_list, "Type", "Name", " for ", subName="Credential")
    
    if aux_str == "":
        aux_str = "No credentials loaded"

    else:
        reloadOptionMenu(credentialSelection, credential_menu, usable_ids)
        aux_str = "Credential generated"

    RSA_key = res_json["Subject Public key"]
    RSA_key_Shortened = RSA_key[:40] + "...." + RSA_key[-40:]
    res_json["Subject Public key"] = RSA_key_Shortened

    mbox.showinfo("Result", json.dumps(res_json, indent=4))
    return plain_credential_list

def encryptOnSgx(responseSelection, response_menu,credentialSelection, credential_menu, compressedPublicECKey):
        credentialPosition = credentialSelection.get()
        position = int(credentialPosition.split(':')[0])

        data = popOne("credentials_issuer", "plain_credentials", position)
        data_json = json.loads(data)
        data_json["Issuer public key"] = compressedPublicECKey
        data = json.dumps(data_json)
        plain_credential_list = getAll("credentials_issuer" ,"plain_credentials")
        req_json = apiCall("encryptbn256", data)
        req_str = json.dumps(req_json)

        _, usable_ids_plain = createIdsAndString(plain_credential_list, "Type", "Name", " for ", subName="Credential")
        reloadOptionMenu(credentialSelection, credential_menu, usable_ids_plain)

        setOne("credentials_issuer", "encrypted_credentials", req_str)

        enc_credential_list = getAll("credentials_issuer" ,"encrypted_credentials")

        aux_str, usable_ids = createIdsAndString(enc_credential_list, "Type", "Name", " for ", subName="Credential", endingLabel="(encrypted)")
        
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

def sendCredential(responseSelection, response_menu):
    enc_credentialPosition = responseSelection.get()
    position = int(enc_credentialPosition.split(':')[0])

    enc_credential = popOne("credentials_issuer", "encrypted_credentials", position)
    enc_cred_list = getAll("credentials_issuer", "encrypted_credentials")

    _, usable_ids_enc = createIdsAndString(enc_cred_list, "Type", "Name", " for ", subName="Credential", endingLabel="(encrypted)")
    reloadOptionMenu(responseSelection, response_menu, usable_ids_enc)

    print(enc_credential)
    pendingRequests_json = rpcCall("credential", enc_credential)
    print(pendingRequests_json)

    mbox.showinfo("Result", "Credential sent to user")

def retrieveLockKeys(lock_key_Selection, lock_key_menu):
    pendingLockKeys_json = rpcCall("pendingLockKeys")
    setMultiple("lock_keys_issuer", "lock_keys", pendingLockKeys_json["result"]["lock_keys"]) 

    list_waiting_lock_keys = pendingLockKeys_json["result"]["lock_keys"]
    complete_list_lock_keys = getAll("lock_keys_issuer", "lock_keys")

    aux_str, _ = createIdsAndString(list_waiting_lock_keys, "key", "DID", " for ")
    if aux_str == "":
        aux_str = "No requests pending"

    else:
        _, usable_ids = createIdsAndString(complete_list_lock_keys, "key", "DID", " for ")
        reloadOptionMenu(lock_key_Selection, lock_key_menu, usable_ids)

    mbox.showinfo("Result", "Unlock keys requests retrieved")

def sendInvoice(lock_key_Selection,bankPrivateECKey):
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

def retrievePayments(payment_Selection, payment_menu):
    payments_json = rpcCall("pendingPayments")
    setMultiple("payments_issuer", "payments", payments_json["result"]["payments"])

    list_waiting_payments = payments_json["result"]["payments"]
    complete_list_payments = getAll("payments_issuer", "payments")

    aux_str, _ = createIdsAndString(list_waiting_payments, "challenge", "DID", " for ")
    if aux_str == "":
        aux_str = "No requests pending"

    else:
        _, usable_ids = createIdsAndString(complete_list_payments, "challenge", "DID", " for ")
        reloadOptionMenu(payment_Selection, payment_menu, usable_ids)
        aux_str = "Payments retrieved"

    mbox.showinfo("Result", aux_str)

def checkBalance():
    balance = checkBalance()
    mbox.showinfo("Result", "Your balance is " + str(balance))

def settlePaymentAndCommitKey(payment_Selection):
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