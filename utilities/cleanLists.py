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

deleteAll("credentials_serviceP", "encrypted_credentials")
deleteAll("credentials_serviceP", "encrypted_credentials_withK")
deleteAll("credentials_serviceP", "plain_credentials")
print(getAll("credentials_serviceP"))

deleteAll("lock_keys_issuer", "lock_keys")
print(getAll("lock_keys_issuer"))

deleteAll("invoices_serviceP", "invoices")
deleteAll("invoices_serviceP", "ephPrivKeys")
print(getAll("invoices_serviceP"))
