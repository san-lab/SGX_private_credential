import json
import copy

requests = {"request": []}
credentials = {"credentials": []}

def getPendingRequests():
    returnedValue = copy.deepcopy(requests)
    requests["request"] = []
    return returnedValue


def getCredentials():
    returnedValue = copy.deepcopy(credentials)
    credentials["credentials"] = []
    print(credentials)
    return returnedValue


def pushNewRequest(req):
    print(req)
    requests["request"].append(req)
    print(requests)


def pushNewCredential(req):
    print(req)
    credentials["credentials"].append(req)
    print(credentials)
