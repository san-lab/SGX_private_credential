import requests
import json

RPC_SERVER_ENDPOINT = 'http://localhost:3000/jsonrpc'
API_SERVER_ENDPOINT = 'http://40.120.61.169:8080/'

data = {
    "jsonrpc": "2.0",
    "method": None,
    "id": 1,
    "params": []
}


def rpcCall(method, parameters=None):

    data["method"] = method
    if parameters == None:
        data["params"] = []
    else:
        data["params"] = [parameters]

    print(data)

    response = requests.post(
            RPC_SERVER_ENDPOINT, data=json.dumps(data))
    return response.json()

def apiCall(verb, data, pickHeader=None):

    response = requests.get(
            API_SERVER_ENDPOINT + verb, data=data)
    
    responseJSON = response.json()
    if pickHeader != None:
        responseJSON[pickHeader] = response.headers.get(pickHeader)

    return responseJSON