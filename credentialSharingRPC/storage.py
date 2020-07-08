import json
import copy

requests = {"request": []}
credentials = {"credentials": []}
presentations = {"presentations": []}
lock_keys = {"lock_keys": []} #TODO requesterDID
unlock_keys = {"unlock_keys": []} #{"DID":124, "unlock_key": "234bca", "lock_key": "ab432"}

def getPendingRequests():
    returnedValue = copy.deepcopy(requests)
    requests["request"] = []
    return returnedValue


def getCredentials():
    returnedValue = copy.deepcopy(credentials)
    credentials["credentials"] = []
    return returnedValue

def getPresentations():
    returnedValue = copy.deepcopy(presentations)
    presentations["presentations"] = []
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

def pushNewPresentation(req):
    print(req)
    presentations["presentations"].append(req)
    print(presentations)

def pushNewLockKey(req):
    print(req)
    lock_keys["lock_keys"].append(req)
    print(lock_keys)

def pushNewUnlockKey(req):
    print(req)
    unlock_keys["unlock_keys"].append(req)
    print(unlock_keys)
