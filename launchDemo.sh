#!/bin/bash

export PYTHONPATH=$PYTHONPATH:$(pwd)
python3 credentialSharingRPC/server.py &
python3 IssuerApp/Issuer_GUI.py &
python3 ServiceProviderApp/Service_GUI.py &
python3 UserApp/User_GUI.py &