from tkinter import *
from tkinter import _setit
import json


def reloadOptionMenu(selectionObject, option_menu, list_ids):
    selectionObject.set('')
    option_menu['menu'].delete(0, 'end')

    # Insert list of new options (tk._setit hooks them up to var)
    count = 0
    for _id in list_ids:
        option_menu['menu'].add_command(label=_id, command=_setit(selectionObject, _id))
        count = count+1

def createIdsAndString(list_to_traverse, json_string, field1, field2, link, endingLabel=None, subName=None):
    aux_str = ""
    usable_ids = list()
    for i in range(0, len(list_to_traverse)):
        if json_string:
            elem = list_to_traverse[i]
            elem_json = json.loads(elem)
        else:
            elem_json = list_to_traverse[i]

        if (subName != None):
            elem_json = elem_json[subName]
        print("HOLA")
        print(elem_json)
        new_id = str(i) + ": " + elem_json[field1] + link + elem_json[field2]
        if (endingLabel != None):
            new_id += endingLabel + "\n"
        else:
            new_id += "\n"
        usable_ids.append(new_id)
        aux_str = aux_str + new_id

    return aux_str, usable_ids


