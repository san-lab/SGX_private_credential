from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import binascii
import os
import sha3
import time

import json
from web3 import Web3

httpAddress = 'https://rinkeby.infura.io/v3/f2a8581c640340758bead17199084148'
AssetUnlockerContractAddress =  '0xe70dc1c9bc6b3b488f1cbc5f48f6772a47a174e5'
private_key = '0x2659d295cf455bc033e5b5ec59afc67057425af8a71a694a5f59ad0e6b333f0c'
account_address = '0xc8dfCA661A53bC05EC1BC76d20Ba77C34F8facAb'

private_keyIss = '0xae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f'
account_addressIss = '0xf17f52151EbEF6C7334FAD080c5704D77216b732'

print(os.path.dirname(os.path.abspath(__file__)))
RELATIVE_FILE_PATH = os.path.dirname(os.path.abspath(__file__)) + '/'

w3 = Web3(Web3.HTTPProvider(httpAddress))
address = Web3.toChecksumAddress(AssetUnlockerContractAddress)

with open(RELATIVE_FILE_PATH + "AssetUnlockerABI.json") as f:
    ABI = json.load(f)

myContract = w3.eth.contract(address=address, abi=ABI)


def payKeyInvoice(challenge):
    nonce = w3.eth.getTransactionCount(account_address)
    builtTransaction = myContract.functions.commitAsset(challenge).buildTransaction({
        'chainId': 4,
        'gas': 4600000,
        'gasPrice': w3.toWei('1', 'gwei'),
        'nonce': nonce,
    })

    signed_txn = w3.eth.account.sign_transaction(builtTransaction, private_key=private_key)
    result = w3.eth.sendRawTransaction(signed_txn.rawTransaction)

    while True:
        try:
            transactionResult = w3.eth.getTransactionReceipt(result)
            print("Point commited to blockchain: ", challenge)
            break
        except:
            print('transaction not mined yet, waiting 5 seconds...')
            time.sleep(5)

    print("\n##########################################################\n")
    transactionLink = "https://rinkeby.etherscan.io/tx/" + transactionResult['transactionHash'].hex()
    print(transactionLink)

def settlePayKeyInvoice(challenge, solution):
    nonceIss = w3.eth.getTransactionCount(account_addressIss)
    builtTransaction = myContract.functions.unlockAsset(challenge, solution).buildTransaction({
        'chainId': 4,
        'gas': 4600000,
        'gasPrice': w3.toWei('1', 'gwei'),
        'nonce': nonceIss,
    })

    signed_txn = w3.eth.account.sign_transaction(builtTransaction, private_key=private_keyIss)
    result = w3.eth.sendRawTransaction(signed_txn.rawTransaction)

    while True:
        try:
            transactionResult = w3.eth.getTransactionReceipt(result)
            print("The issuer sends s for verification:    ", s, "\n")
            break
        except:
            print('transaction not mined yet, waiting 5 seconds...')
            time.sleep(5)

    print("\n##########################################################\n")
    transactionLink = "https://rinkeby.etherscan.io/tx/" + transactionResult['transactionHash'].hex()
    print(transactionLink)

def checkBalance():
    return myContract.caller.checkBalance(account_addressIss, account_address)

def getKeyFromBlockchain():
    return myContract.caller.getKey(PL.x)
