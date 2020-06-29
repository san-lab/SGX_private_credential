from jsonrpc import dispatcher
from storage import pushNewRequest, getPendingRequests

def serviceLookUp():
    return {'type': ' ring signature service', 'curve': 'cosa', 'hashing algortithm': 'keccak'}

def acceptNewCredentialRequest(data):
    pushNewRequest(data)
    return {'message': 'The request will be evaluated shortly', 'credential': data['type']}

def showNewCredentialRequest():
    return getPendingRequests()

dispatcher['serviceLookUp'] = serviceLookUp
dispatcher['credentialRequest'] = acceptNewCredentialRequest
dispatcher['pendingRequests'] = showNewCredentialRequest