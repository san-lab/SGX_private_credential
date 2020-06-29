from jsonrpc import dispatcher

def serviceLookUp():
    return {'type': ' ring signature service', 'curve': 'cosa', 'hashing algortithm': 'keccak'}

def acceptNewCredentialRequest(data):
    return {'message': 'The request will be evaluated shortly', 'credential': data['type']}

dispatcher['serviceLookUp'] = serviceLookUp
dispatcher['credentialRequest'] = acceptNewCredentialRequest