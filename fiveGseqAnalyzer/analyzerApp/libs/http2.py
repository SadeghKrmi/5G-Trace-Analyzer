
from libs.pcapfunctions import pcapjsonfilterSingleParent
import json
from functools import reduce  # forward compatibility for Python 3
import operator
import pymongo


connectionToMongo = 'mongodb://localhost:27017/'

streamid_definitions = {}

def getFromDict(dataDict, mapList):
    return reduce(operator.getitem, mapList, dataDict)


def setInDict(dataDict, mapList, value):
    getFromDict(dataDict, mapList[:-1])[mapList[-1]] = value


def JsonInspector(data, field, path=[]):
    for key, value in data.items():
        path.append(key)
        if field == key:
            yield path
        if isinstance(value, dict):
            yield from JsonInspector(value, field, path)
        path.pop()


def jsonOrganizer(jsonData, streamId, streamType):
    if 'json.object' in jsonData:
        jsonData['json.key'] = 'http2'
        http2_payload = list(JsonWrapperData(jsonData))
        http2_payload = http2_payload[0]
        http2_payload['streamid'] = streamId
        http2_payload['type'] = streamType
    elif 'json.array' in jsonData :
        if isinstance(jsonData.get('json.array'), dict):
            jsonData['json.key'] = 'http2'
            http2_payload = list(JsonWrapperData(jsonData))
            http2_payload = http2_payload[0]
            http2_payload['streamid'] = streamId
            http2_payload['type'] = streamType
        else:
            http2_payload = jsonData
    else:
        http2_payload = jsonData

    return http2_payload

# Json Wrapper to nested dict of lists
def JsonWrapperData(data):
    if isinstance(data, dict):
        if 'json.object' in data.keys():
            objects = data.get('json.object')
            if isinstance(objects, dict):
                members = data.get('json.object').get('json.member')
                k = data.get('json.key', 'value')
                ele = {}
                for x in JsonWrapperData(members):
                    ele.update(x)
                yield {k: ele}
            elif isinstance(objects, list):
                for item1 in objects:
                    members = item1
                    k = data.get('json.key', 'value')
                    ele = {}
                    for x in JsonWrapperData(members):
                        ele.update(x)
                    yield {k: ele}
            else:
                yield {}
        elif 'json.array' in data.keys():
            array = data.get('json.array')
            k = data.get('json.key')
            eleArray = {}
            for y in JsonWrapperData(array):
                eleArray.update(y)
            yield {k: eleArray}                
        else:
            key = [x for x in data.keys() if x != 'json.keys'][0]
            k = data.get('json.key', 'value')
            element = {k: data.get(key)}
            yield element

    elif isinstance(data, list):
        
        for item in data:
            k = item.get('json.key')
            eleList = {}
            for z in JsonWrapperData(item):
                eleList.update(z)
            yield eleList



def http2Anlayzer(pkt, traceName):

    # connect to DB
    client = pymongo.MongoClient(connectionToMongo)
    db = client['traces_sequence_data']
    col = db['data']

    db2 = client['diagram']
    col2 = db2['http2Form']

    http2_param = col2.find_one({"_id": 2}, {"_id":0})
    header_param = http2_param['header']
    payload_param = http2_param['payload']

    chunk_size = 45 # Characters

    message_lines = []
    http2 = pkt.http2
    packetNumber = str(pkt.number)
    data_http2_layer = dict(http2._all_fields)
    
    stream = http2.stream
    streamId = stream.streamid
    streamType = stream.type
    
    dataInSeq = {}
    #  stream has either header or data field
    #  -----------------------------------------------------------------------
    if stream.has_field('header'):
        ShowOnMainLine = header_param.get('ShowOnMainLine', False)
        needFilter = header_param.get('filter', False)
        filterFields = header_param.get('fields', [])

        http2_header = {}
        for header in http2.stream.header:
            http2_header[header.name.strip(":")] = header.value
        
        http2_header['streamid'] = streamId
        http2_header['type'] = streamType
        dataInSeq = http2_header

        # ++++++++++++++++++++++++++ Method 1 ++++++++++++++++++++++++++++++
        # Use Method 1 for shorter graph 
        # main_line = {'text': 'http2 header transaction', 'color': 'blue'}
        # message_lines = [main_line]

        print('------------- Http2: packet Number {ix}, MessageType: header -------------'.format(ix=packetNumber))

        # ++++++++++++++++++++++++++ Method 2 ++++++++++++++++++++++++++++++
        if 'status' in http2_header:
            line_text = '{} {}'.format('status', http2_header.get('status'))
            main_line = {'text': 'http2 Status {}'.format(http2_header.get('status')), 'color': 'blue'}
            message_lines = [main_line]
        elif 'method' in http2_header:
            path_value = str(http2_header.get('path'))
            if len(path_value) > chunk_size:
                all_chunks = [path_value[i:i+chunk_size] for i in range(0, len(path_value), chunk_size)]
                main_line = {'text': 'http2 {} {}'.format(http2_header.get('method'), all_chunks[0]), 'color': 'blue'}
                message_lines = [main_line]
                for chunk_element in all_chunks[1:]:
                    main_line = {'text': '    {}'.format(chunk_element), 'color': 'blue'}
                    message_lines.append(main_line)
            else:
                main_line = {'text': 'http2 {} {}'.format(http2_header.get('method'), path_value), 'color': 'blue'}
                message_lines = [main_line]
        
        if needFilter:
            FilteredDataInSeq = {}
            if isinstance(dataInSeq, dict):
                for fs in filterFields:
                    for ListofKeys in JsonInspector(dataInSeq, fs): 
                        FilteredDataInSeq[fs] = getFromDict(dataInSeq, ListofKeys)

        
        if ShowOnMainLine:
            if needFilter:
                DataToShow = FilteredDataInSeq
            else:
                DataToShow = dataInSeq
            if DataToShow:
                protocolData = json.dumps(DataToShow, indent=2)
                LinesOfData = protocolData.splitlines()
                for lines in LinesOfData:
                    if len(lines) > chunk_size:
                        lx = lines[0:chunk_size] + "_TRUNCATED"
                    else:
                        lx = lines
                    line_text = '{}'.format(lx)
                    message_lines.append({'text': line_text})


    #  -----------------------------------------------------------------------
    elif stream.has_field('data'):
        ShowOnMainLine = payload_param.get('ShowOnMainLine', False)
        needFilter = payload_param.get('filter', False)
        filterFields = payload_param.get('fields', [])

        main_line = {'text': 'http2 Payload transaction', 'color': 'blue'}
        message_lines = [main_line]

        print('------------- Http2: packet Number {ix}, MessageType: payload -------------'.format(ix=packetNumber))
        
        if pkt.http2._all_fields.get('mime_multipart', False):
            mimeDataList = data_http2_layer.get('mime_multipart', {}).get('mime_multipart.part_tree', {})
            if isinstance(mimeDataList, list):
                for mimeItem in mimeDataList:
                    if mimeItem.get('json', False):
                        jsonData = mimeItem.get('json')
                        application = mimeItem.get('mime_multipart.header.content-type')
                        dataInSeq[application] = jsonOrganizer(jsonData, streamId, streamType)
                    else:
                        application = mimeItem.get('mime_multipart.header.content-type')
                        dataInSeq[application] = mimeItem
            elif isinstance(mimeDataList, dict):
                    mimeItem = mimeDataList
                    if mimeItem.get('json', False):
                        jsonData = mimeItem.get('json')
                        dataInSeq = jsonOrganizer(jsonData, streamId, streamType)
                    else:
                        application = mimeItem.get('mime_multipart.header.content-type')
                        dataInSeq[application] = mimeItem
        else:
            jsonData = data_http2_layer.get('json', {})
            dataInSeq = jsonOrganizer(jsonData, streamId, streamType)

        if needFilter:
            FilteredDataInSeq = {}
            if isinstance(dataInSeq, dict):
                for fs in filterFields:
                    for ListofKeys in JsonInspector(dataInSeq, fs): 
                        FilteredDataInSeq[fs] = getFromDict(dataInSeq, ListofKeys)

        
        if ShowOnMainLine:
            if needFilter:
                DataToShow = FilteredDataInSeq
            else:
                DataToShow = dataInSeq
            if DataToShow:
                protocolData = json.dumps(DataToShow, indent=2)
                LinesOfData = protocolData.splitlines()
                for lines in LinesOfData:
                    if len(lines) > chunk_size:
                        lx = lines[0:chunk_size] + "_TRUNCATED"
                    else:
                        lx = lines
                    line_text = '{}'.format(lx)
                    message_lines.append({'text': line_text})

    else:
        raise ValueError('packet http2 layer does not contain header or data')

    #  -----------------------------------------------------------------------
    dataToMongo = {'name': traceName, 'packetNumber': packetNumber, 'data': dataInSeq}
    x = col.insert(dataToMongo, check_keys=False)
    client.close()
    return message_lines
