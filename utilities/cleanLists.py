import sys
sys.path.append('../')
from dao.dao import getAll,deleteAll

deleteAll("credentials_request", "request")
print(getAll("credentials_request"))

deleteAll("credentials_saved", "credentials")
print(getAll("credentials_saved"))

deleteAll("credentials_issuer", "plain_credentials")
deleteAll("credentials_issuer", "encrypted_credentials")
print(getAll("credentials_issuer"))
