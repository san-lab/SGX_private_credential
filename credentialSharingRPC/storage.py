import json
import copy

requests = {"request": []}
credentials = {"credentials": []}
lock_keys = {"lock_keys": [{"DID":123, "key": "ab432"}]}
unlock_keys = {"unlock_keys": [{"DID":124, "key": "234bca"}]}

def getPendingRequests():
    returnedValue = copy.deepcopy(requests)
    requests["request"] = []
    return returnedValue


def getCredentials():
    returnedValue = copy.deepcopy(credentials)
    credentials["credentials"] = []
    return returnedValue

def getLockKeys():
    returnedValue = copy.deepcopy(lock_keys)
    lock_keys["lock_keys"] = []
    return returnedValue

def getUnlockKeys():
    returnedValue = copy.deepcopy(unlock_keys)
    unlock_keys["unlock_keys"] = []
    return returnedValue


def pushNewRequest(req):
    print(req)
    requests["request"].append(req)
    print(requests)


def pushNewCredential(req):
    print(req)
    credentials["credentials"].append(req)
    print(credentials)

def pushNewLockKey(req):
    print(req)
    lock_keys["lock_keys"].append(req)
    print(lock_keys)

def pushNewUnlockKey(req):
    print(req)
    unlock_keys["unlock_keys"].append(req)
    print(unlock_keys)
