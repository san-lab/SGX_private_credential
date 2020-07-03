import requests
import json

RPC_SERVER_ENDPOINT = 'http://localhost:3000/jsonrpc'

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