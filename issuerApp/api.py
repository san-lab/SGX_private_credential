from jsonrpc import dispatcher
from storage import pushNewRequest, getPendingRequests, getCredentials, pushNewCredential

def serviceLookUp():
    return {'type': ' ring signature service', 'curve': 'cosa', 'hashing algortithm': 'keccak'}

def acceptNewCredentialRequest(data):
    pushNewRequest(data)
    return {'message': 'The request will be evaluated shortly', 'credential': data['type']}

def acceptNewCredential(data):
    print("DATA")
    print(data)
    pushNewCredential(data)
    return {'message': 'The credential has been sent', 'credential': data["Credential"]["Type"]}

def showNewCredentialRequest():
    return getPendingRequests()

def showNewCredentials():
    return getCredentials()

dispatcher['serviceLookUp'] = serviceLookUp
dispatcher['credentialRequest'] = acceptNewCredentialRequest
dispatcher['credential'] = acceptNewCredential
dispatcher['pendingRequests'] = showNewCredentialRequest
dispatcher['pendingCredentials'] = showNewCredentials