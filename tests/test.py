import requests
import json

req = requests.get('http://40.120.61.169:8080/issue')
req_json = req.json()

print(json.dumps(req_json))

data = json.dumps(req_json)
req2 = requests.get('http://40.120.61.169:8080/submit', data=data)
req2_json = req2.json()

print(json.dumps(req2_json))