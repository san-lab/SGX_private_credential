#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

from tkinter import *
from tkinter import ttk
from PIL import ImageTk, Image
from tkinter.filedialog import askopenfilename, askdirectory, asksaveasfilename
from tkinter import simpledialog
import pandas as pd
import subprocess
import json
import uuid

from crypto_local.worker import SGXWorkerDetails
from crypto_local.signature import ClientSignature
from crypto_local.signingAlgorithm import signAlgorithm
from crypto_local.encriptionAlg import encAlgorithm


def encryptSGXWorkOrder(workload_json, worker_json):
    ec_file = open("/Users/macblockchain1/Desktop/projects/SGX_private_credential/crypto_local/crypto_test_files/ec.pem", "r")
    EC_key = ec_file.read()

    worker_obj = SGXWorkerDetails()
    worker_obj.load_worker(worker_json)

    #workload_json["params"]["workerId"] = worker_obj.worker_id

    workload_str = json.dumps(workload_json)

    sig_obj = ClientSignature()

    signing_key = signAlgorithm()
    signing_key.loadKey(EC_key)

    session_iv = sig_obj.generate_sessioniv()

    enc_obj = encAlgorithm()
    session_key = enc_obj.generateKey()
    
    #session_key = tuple([86, 128, 132, 43, 225, 3, 186, 79, 134, 146, 119, 231, 238, 39, 220, 58, 80, 105, 72, 4, 241, 130, 223, 66, 82, 96, 194, 47, 134, 19, 41, 34])
    #session_iv = tuple([117, 172, 29, 141, 226, 236, 195, 169, 142, 182, 248, 52])


    enc_session_key = sig_obj.generate_encripted_key(session_key,worker_obj.encryption_key)

    request_json = sig_obj.generate_client_signature(workload_str,worker_obj,signing_key, session_key, session_iv, enc_session_key)

    enc_session_json = '{"key": ' + str(list(enc_session_key)) + '}'

    return request_json, enc_session_json
