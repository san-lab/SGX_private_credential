import json

requests = {"request": [{"name": "Alice", "type": "credit scoring", "DID": "342"}, {
    "name": "Bob", "type": "credit scoring", "DID": "265"}]}
credentials = {
    "credentials": [
        {"Credential": {"Type": "Credit scoring", "Name": "Alice", "DID": "42", "score": {"encrypted": False, "value": "A Plus"}, "lock key": {"encrypted": False, "value": "x"}}, "Issuer name": "Banco Santander", "Issuer public key": {
            "Issuer Public key": "6cc0580343356515c288897c68dad03a2063d1ea9c03c14af40174bef52d1503", "Issuer Public key x": "53d8775849f6eeea72adb402f64df032641ebc390e12c9fd364bbb521606e712", "Issuer Public key y": "03152df5be7401f44ac1039cead163203ad0da687c8988c2156535430358c06c"}, "Subjec's Public key": "RSA_PEM_Here"}
    ]
}


def getPendingRequests():
    print(requests)
    return requests


def getCredentials():
    print(credentials)
    return credentials


def pushNewRequest(req):
    print(req)
    requests["request"].append(req)
    print(requests)


def pushNewCredential(req):
    print(req)
    credentials["credentials"].append(req)
    print(credentials)
