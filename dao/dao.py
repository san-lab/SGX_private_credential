import json

RELATIVE_FILE_PATH = "../dao/"

def getAll(fileName, subName=None):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    if(subName != None):
        data_json = data_json[subName]
    data_file.close()
    return data_json

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

def deleteOne(fileName, subName, position):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    data_file.close()
    data_json[subName] = data_json[subName].pop(position)

    data_file_write = open(RELATIVE_FILE_PATH + fileName + ".json", "w")
    data_file_write.write(json.dumps(data_json))
    data_file_write.close()

def deleteAll(fileName, subName):
    data_file = open(RELATIVE_FILE_PATH + fileName + ".json", "r")
    data_str = data_file.read()
    data_json = json.loads(data_str)
    data_file.close()
    data_json[subName] = []

    data_file_write = open(RELATIVE_FILE_PATH + fileName + ".json", "w")
    data_file_write.write(json.dumps(data_json))
    data_file_write.close()
