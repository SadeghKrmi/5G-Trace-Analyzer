import pymongo
client = pymongo.MongoClient('mongodb://172.17.0.3:27017/')
db = client['diagram']
col = db["http2Form"]

http2 = {
    'header': {
        'filter': False, 'fields': [], 'ShowOnMainLine': False
    },
    'payload': {
        'filter': False, 'fields': [], 'ShowOnMainLine': False
    },
}



x = col.delete_one({"_id":1})
x = col.delete_one({"_id":2})
x = col.insert_one({"_id": 1, "http2": http2})
x = col.insert_one({"_id": 2, "http2": http2})