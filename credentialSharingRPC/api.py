from jsonrpc import dispatcher
from storage import pushNewRequest, getPendingRequests, getCredentials, pushNewCredential, pushNewLockKey, pushNewUnlockKey, getLockKeys, getUnlockKeys, pushNewPresentation, getPresentations

def serviceLookUp():
    return {'type': ' ring signature service', 'curve': 'cosa', 'hashing algortithm': 'keccak'}

def acceptNewCredentialRequest(data):
    pushNewRequest(data)
    return {'message': 'The request will be evaluated shortly', 'credential': data['type']}

def acceptNewCredential(data):
    pushNewCredential(data)
    return {'message': 'The credential has been sent', 'credential': data["Credential"]["Type"]}

def acceptNewPresentation(data):
    pushNewPresentation(data)
    return {'message': 'The presentation has been sent', 'credential': data["Credential"]["Type"]}

def acceptNewLockKey(data):
    pushNewLockKey(data)
    return {'message': 'Lock key has been sent', 'key_type': 'ec compressed point'}

def acceptNewUnlockKey(data):
    pushNewUnlockKey(data)
    return {'message': 'Unlock key has been sent', 'key_type': 'AES symmetric key'}

def showNewCredentialRequest():
    return getPendingRequests()

def showNewCredentials():
    return getCredentials()

def showNewPresentations():
    return getPresentations()

def showNewLockKeys():
    return getLockKeys()

def showNewUnlockKeys():
    return getUnlockKeys()

dispatcher['serviceLookUp'] = serviceLookUp
dispatcher['credentialRequest'] = acceptNewCredentialRequest
dispatcher['credential'] = acceptNewCredential
dispatcher['presentation'] = acceptNewPresentation
dispatcher['lockKey'] = acceptNewLockKey
dispatcher['unlockKey'] = acceptNewUnlockKey
dispatcher['pendingRequests'] = showNewCredentialRequest
dispatcher['pendingCredentials'] = showNewCredentials
dispatcher['pendingPresentations'] = showNewPresentations
dispatcher['pendingLockKeys'] = showNewLockKeys
dispatcher['pendingUnlockKeys'] = showNewUnlockKeys