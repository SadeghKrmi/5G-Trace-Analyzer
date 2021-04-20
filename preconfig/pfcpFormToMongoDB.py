import pymongo
client = pymongo.MongoClient('mongodb://172.17.0.3:27017/')
db = client['diagram']
col = db["pfcpForm"]

pfcp_messages = {
    '1' : {'name': 'Heartbeat Request             ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '2' : {'name': 'Heartbeat Response            ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '3' : {'name': 'PFD Management Request        ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '4' : {'name': 'PFD Management Response       ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '5' : {'name': 'Association Setup Request     ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '6' : {'name': 'Association Setup Response    ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '7' : {'name': 'Association Update Request    ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '8' : {'name': 'Association Update Response   ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '9' : {'name': 'Association Release Request   ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '10': {'name': 'Association Release Response  ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '11': {'name': 'Version Not Supported Response', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '12': {'name': 'Node Report Request           ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '13': {'name': 'Node Report Response          ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '14': {'name': 'Session Set Deletion Request  ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '15': {'name': 'Session Set Deletion Response ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '50': {'name': 'Session Establishment Request ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '51': {'name': 'Session Establishment Response', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '52': {'name': 'Session Modification Request  ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '53': {'name': 'Session Modification Response ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '54': {'name': 'Session Deletion Request      ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '55': {'name': 'Session Deletion Response     ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '56': {'name': 'Session Report Request        ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    '57': {'name': 'Session Report Response       ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
    }
    
x = col.delete_one({"_id":1})
x = col.delete_one({"_id":2})
x = col.insert_one({"_id": 1, "pfcp_messages": pfcp_messages})
x = col.insert_one({"_id": 2, "pfcp_messages": pfcp_messages})
