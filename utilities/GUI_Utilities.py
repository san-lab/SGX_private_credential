from tkinter import *
from tkinter import _setit
import json
from dao.dao import getAll

def button(tkDialog, bText, bRow, bFunc):
        b = ttk.Button(
            tkDialog, text=bText,
            command=bFunc)
        b.grid(row=bRow, sticky='ew', pady=(11, 7), padx=(25, 0))

def multipleSelect(tkDialog, sList, sRow):
        selection = StringVar(tkDialog)
        selection.set(sList[0]) # default value
        menu = OptionMenu(tkDialog, selection, *sList)
        menu.grid(row=sRow, sticky='ew', pady=(11, 7), padx=(25, 0))
        return selection, menu

def loadLists(fileName, subName, sEndingLabel, selection, menu):
        tempList = getAll(fileName, subName)
        _, usable_ids = createIdsAndString(tempList, "Type", "Name", " for ", subName="Credential", endingLabel=sEndingLabel)
        reloadOptionMenu(selection, menu, usable_ids)


def reloadOptionMenu(selectionObject, option_menu, list_ids):
    selectionObject.set('')
    option_menu['menu'].delete(0, 'end')

    # Insert list of new options (tk._setit hooks them up to var)
    count = 0
    for _id in list_ids:
        option_menu['menu'].add_command(label=_id, command=_setit(selectionObject, _id))
        count = count+1

def createIdsAndString(list_to_traverse, field1, field2, link, endingLabel=None, subName=None):
    aux_str = ""
    usable_ids = list()
    for i in range(0, len(list_to_traverse)):
        if type(list_to_traverse[i]) == str:
            elem = list_to_traverse[i]
            elem_json = json.loads(elem)
        else:
            elem_json = list_to_traverse[i]

        if (subName != None):
            elem_json = elem_json[subName]
        print(elem_json)
        new_id = str(i) + ": " + str(elem_json[field1]) + link + str(elem_json[field2])
        if (endingLabel != None):
            new_id += endingLabel + "\n"
        else:
            new_id += "\n"
        usable_ids.append(new_id)
        aux_str = aux_str + new_id

    return aux_str, usable_ids

def createIdsAndStringSpecialCase(list_to_traverse):
    aux_str = ""
    usable_ids = list()
    for i in range (0,len(list_to_traverse)):
        cred_json = list_to_traverse[i]
        new_id = str(i) + ": " + cred_json["Credential"]["Type"] + " by " + cred_json["Issuer name"] + "\n"
        usable_ids.append(new_id)
        aux_str = aux_str + new_id + "\n"
    return aux_str, usable_ids


