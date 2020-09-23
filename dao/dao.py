import json
import os

print(os.path.dirname(os.path.abspath(__file__)))
RELATIVE_FILE_PATH = os.path.dirname(os.path.abspath(__file__)) + '/'

def getAll(fileName, subName=None):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    if(subName != None):
        data_json = data_json[subName]
    data_file.close()
    return data_json

def getOne(fileName, subName, position):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    data_file.close()
    return data_json[subName][position]

def setOne(fileName, subName, item):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    data_file.close()

    data_json[subName].append(item)

    data_file_write = open(RELATIVE_FILE_PATH + fileName + ".json", "w")
    data_file_write.write(json.dumps(data_json))
    data_file_write.close()

def setMultiple(fileName, subName, itemList):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    data_file.close()

    data_json[subName] += itemList

    data_file_write = open(RELATIVE_FILE_PATH + fileName + ".json", "w")
    data_file_write.write(json.dumps(data_json))
    data_file_write.close()

def popOne(fileName, subName, position):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    data_file.close()
    element = data_json[subName].pop(position)

    data_file_write = open(RELATIVE_FILE_PATH + fileName + ".json", "w")
    data_file_write.write(json.dumps(data_json))
    data_file_write.close()
    return element

def deleteAll(fileName, subName):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    data_file.close()
    data_json[subName] = []

    data_file_write = open(RELATIVE_FILE_PATH + fileName + ".json", "w")
    data_file_write.write(json.dumps(data_json))
    data_file_write.close()
