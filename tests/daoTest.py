import sys
sys.path.append('../')
from dao.dao import getAll, setOne, setMultiple, deleteOne


print(getAll("credentials_request", "request"))

setOne("credentials_request", "request",{"name": "Maria", "type": "Bad payer cert", "DID": "1234"})

setMultiple("credentials_request", "request",[{"name": "Paco", "type": "Bad payer cert", "DID": "1234"},{"name": "Jose", "type": "Bad payer cert", "DID": "1234"}])

print(getAll("credentials_request", "request"))

deleteOne("credentials_request", "request", 2)

print(getAll("credentials_request", "request"))

