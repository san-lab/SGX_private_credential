import json

requests = {"request": [{"name": "Alice", "type": "credit scoring", "DID": "342"}, {"name": "Bob", "type": "credit scoring", "DID": "265"}]}

def getPendingRequests():
    print (requests )
    return requests

def pushNewRequest(req):
    print ( req )
    requests["request"].append(req)
    print ( requests )
