import json

requests = {"request": [{"user": "Alice", "type": "credit scoring", "DID": 342}, {"user": "Bob", "type": "credit scoring", "DID": 265}]}

def getPendingRequests():
    print (requests )
    return requests

def pushNewRequest(req):
    print ( req )
    requests["request"].append(req)
    print ( requests )
