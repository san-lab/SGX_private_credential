import sys
sys.path.append('../')
from utilities.communicationToRPC import rpcCall

print(rpcCall("pendingLockKeys"))
print(rpcCall("lockKey", {"key": "123", "DID": 453}))
print(rpcCall("pendingLockKeys"))