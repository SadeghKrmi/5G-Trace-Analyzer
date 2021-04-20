# this is pfcp analyizer

from libs.pcapfunctions import pcapjsonfilterSingleParent
import json
from functools import reduce
import operator
import pymongo

connectionToMongo = 'mongodb://localhost:27017/'

client = pymongo.MongoClient(connectionToMongo)
db = client['diagram']
col = db["pfcpForm"]
result = col.find_one({"_id":2}, {"_id":0})
pfcp_messages = result['pfcp_messages']
client.close()
# print(pfcp_messages)
# 7.3 of TS 29.244
# pfcp_messages = {
#     '1' : {'name': 'Heartbeat Request             ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '2' : {'name': 'Heartbeat Response            ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '3' : {'name': 'PFD Management Request        ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '4' : {'name': 'PFD Management Response       ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '5' : {'name': 'Association Setup Request     ', 'required': False, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '6' : {'name': 'Association Setup Response    ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '7' : {'name': 'Association Update Request    ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '8' : {'name': 'Association Update Response   ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '9' : {'name': 'Association Release Request   ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '10': {'name': 'Association Release Response  ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '11': {'name': 'Version Not Supported Response', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '12': {'name': 'Node Report Request           ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '13': {'name': 'Node Report Response          ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '14': {'name': 'Session Set Deletion Request  ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '15': {'name': 'Session Set Deletion Response ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '50': {'name': 'Session Establishment Request ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '51': {'name': 'Session Establishment Response', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '52': {'name': 'Session Modification Request  ', 'required': True, 'filter': False, 'fields': [57, 9, 56], 'ShowOnMainLine': True},
#     '53': {'name': 'Session Modification Response ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '54': {'name': 'Session Deletion Request      ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '55': {'name': 'Session Deletion Response     ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '56': {'name': 'Session Report Request        ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     '57': {'name': 'Session Report Response       ', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     }


pfcp_ie_types = {
    '1'  :	'Create PDR',
    '2'  :	'PDI',
    '3'  :	'Create FAR',
    '4'  :	'Forwarding Parameters',
    '5'  :	'Duplicating Parameters',
    '6'  :	'Create URR',
    '7'  :	'Create QER',
    '8'  :	'Created PDR',
    '9'  :	'Update PDR',
    '10' :	'Update FAR',
    '11' :	'Update Forwarding Parameters',
    '12' :	'Update BAR (PFCP Session Report Response)',
    '13' :	'Update URR',
    '14' :	'Update QER',
    '15' :	'Remove PDR',
    '16' :	'Remove FAR',
    '17' :	'Remove URR',
    '18' :	'Remove QER',
    '19' :	'Cause',
    '20' :	'Source Interface',
    '21' :	'F-TEID',
    '22' :	'Network Instance',
    '23' :	'SDF Filter',
    '24' :	'Application ID',
    '25' :	'Gate Status',
    '26' :	'MBR',
    '27' :	'GBR',
    '28' :	'QER Correlation ID',
    '29' :	'Precedence',
    '30' :	'Transport Level Marking',
    '31' :	'Volume Threshold',
    '32' :	'Time Threshold',
    '33' :	'Monitoring Time',
    '34' :	'Subsequent Volume Threshold',
    '35' :	'Subsequent Time Threshold',
    '36' :	'Inactivity Detection Time',
    '37' :	'Reporting Triggers',
    '38' :	'Redirect Information',
    '39' :	'Report Type',
    '40' :	'Offending IE',
    '41' :	'Forwarding Policy',
    '42' :	'Destination Interface',
    '43' :	'UP Function Features',
    '44' :	'Apply Action',
    '45' :	'Downlink Data Service Information',
    '46' :	'Downlink Data Notification Delay',
    '47' :	'DL Buffering Duration',
    '48' :	'DL Buffering Suggested Packet Count',
    '49' :	'PFCPSMReq-Flags',
    '50' :	'PFCPSRRsp-Flags',
    '51' :	'Load Control Information',
    '52' :	'Sequence Number',
    '53' :	'Metric',
    '54' :	'Overload Control Information',
    '55' :	'Timer',
    '56' :	'Packet Detection Rule ID',
    '57' :	'F-SEID',
    '58' :	'Application IDs PFDs',
    '59' :	'PFD context',
    '60' :	'Node ID',
    '61' :	'PFD contents',
    '62' :	'Measurement Method',
    '63' :	'Usage Report Trigger',
    '64' :	'Measurement Period',
    '65' :	'FQ-CSID',
    '66' :	'Volume Measurement',
    '67' :	'Duration Measurement',
    '68' :	'Application Detection Information',
    '69' :	'Time of First Packet',
    '70' :	'Time of Last Packet',
    '71' :	'Quota Holding Time',
    '72' :	'Dropped DL Traffic Threshold',
    '73' :	'Volume Quota',
    '74' :	'Time Quota',
    '75' :	'Start Time',
    '76' :	'End Time',
    '77' :	'Query URR',
    '78' :	'Usage Report (Session Modification Response)',
    '79' :	'Usage Report (Session Deletion Response)',
    '80' :	'Usage Report (Session Report Request)',
    '81' :	'URR ID',
    '82' :	'Linked URR ID',
    '83' :	'Downlink Data Report',
    '84' :	'Outer Header Creation',
    '85' :	'Create BAR',
    '86' :	'Update BAR (Session Modification Request)',
    '87' :	'Remove BAR',
    '88' :	'BAR ID',
    '89' :	'CP Function Features',
    '90' :	'Usage Information',
    '91' :	'Application Instance ID',
    '92' :	'Flow Information',
    '93' :	'UE IP Address',
    '94' :	'Packet Rate',
    '95' :	'Outer Header Removal',
    '96' :	'Recovery Time Stamp',
    '97' :	'DL Flow Level Marking',
    '98' :	'Header Enrichment',
    '99' :	'Error Indication Report',
    '100 ':	'Measurement Information',
    '101':	'Node Report Type',
    '102':	'User Plane Path Failure Report',
    '103':	'Remote GTP-U Peer',
    '104':	'UR-SEQN',
    '105':	'Update Duplicating Parameters',
    '106':	'Activate Predefined Rules',
    '107':	'Deactivate Predefined Rules',
    '108':	'FAR ID',
    '109':	'QER ID',
    '110':	'OCI Flags',
    '111':	'PFCP Association Release Request',
    '112':	'Graceful Release Period',
    '113':	'PDN Type',
    '114':	'Failed Rule ID',
    '115':	'Time Quota Mechanism',
    '116':	'User Plane IP Resource Information',
    '117':	'User Plane Inactivity Timer',
    '118':	'Aggregated URRs',
    '119':	'Multiplier',
    '120':	'Aggregated URR ID',
    '121':	'Subsequent Volume Quota',
    '122':	'Subsequent Time Quota',
    '123':	'RQI',
    '124':	'QFI',
    '125':	'Query URR Reference',
    '126':	'Additional Usage Reports Information',
    '127':	'Create Traffic Endpoint',
    '128':	'Created Traffic Endpoint',
    '129':	'Update Traffic Endpoint',
    '130':	'Remove Traffic Endpoint',
    '131':	'Traffic Endpoint ID',
    '132':	'Ethernet Packet Filter',
    '133':	'MAC address',
    '134':	'C-TAG',
    '135':	'S-TAG',
    '136':	'Ethertype',
    '137':	'Proxying',
    '138':	'Ethernet Filter ID',
    '139':	'Ethernet Filter Properties',
    '140':	'Suggested Buffering Packets Count',
    '141':	'User ID',
    '142':	'Ethernet PDU Session Information',
    '143':	'Ethernet Traffic Information',
    '144':	'MAC Addresses Detected',
    '145':	'MAC Addresses Removed',
    '146':	'Ethernet Inactivity Timer',
    '147':	'Additional Monitoring Time',
    '148':	'Event Quota',
    '149':	'Event Threshold',
    '150':	'Subsequent Event Quota',
    '151':	'Subsequent Event Threshold',
    '152':	'Trace Information',
    '153':	'Framed-Route',
    '154':	'Framed-Routing',
    '155':	'Framed-IPv6-Route',
    '156':	'Event Time Stamp',
    '157':	'Averaging Window',
    '158':	'Paging Policy Indicator',
    '159':	'APN/DNN',
    '160':	'3GPP Interface Type',
    '161':	'PFCPSRReq-Flags',
    '162':	'PFCPAUReq-Flags',
    '163':	'Activation Time',
    '164':	'Deactivation Time',
    '165':	'Create MAR',
    '166':	'3GPP Access Forwarding Action Information',
    '167':	'Non-3GPP Access Forwarding Action Information',
    '168':	'Remove MAR',
    '169':	'Update MAR',
    '170':	'MAR ID',
    '171':	'Steering Functionality',
    '172':	'Steering Mode',
    '173':	'Weight',
    '174':	'Priority',
    '175':	'Update 3GPP Access Forwarding Action Information',
    '176':	'Update Non 3GPP Access Forwarding Action Information',
    '177':	'UE IP address Pool Identity',
    '178':	'Alternative SMF IP Address',
    '179':	'Packet Replication and Detection Carry-On Information',
    '180':	'SMF Set ID',
    '181':	'Quota Validity Time',
    '182':	'Number of Reports',
    '183':	'PFCP Session Retention Information (within PFCP Association Setup Request)',
    '184':	'PFCPASRsp-Flags',
    '185':	'CP PFCP Entity IP Address',
    '186':	'PFCPSEReq-Flags',
    '187':	'User Plane Path Recovery Report',
    '188':	'IP Multicast Addressing Info within PFCP Session Establishment Request',
    '189':	'Join IP Multicast Information IE within Usage Report',
    '190':	'Leave IP Multicast Information IE within Usage Report',
    '191':	'IP Multicast Address',
    '192':	'Source IP Address',
    '193':	'Packet Rate Status',
    '194':	'Create Bridge Info for TSC',
    '195':	'Created Bridge Info for TSC',
    '196':	'DS-TT Port Number',
    '197':	'NW-TT Port Number',
    '198':	'TSN Bridge ID',
    '199':	'Port Management Information for TSC IE within PFCP Session Modification Request',
    '200':	'Port Management Information for TSC IE within PFCP Session Modification Response',
    '201':	'Port Management Information for TSC IE within PFCP Session Report Request',
    '202':	'Port Management Information Container',
    '203':	'Clock Drift Control Information',
    '204':	'Requested Clock Drift Information',
    '205':	'Clock Drift Report',
    '206':	'TSN Time Domain Number',
    '207':	'Time Offset Threshold',
    '208':	'Cumulative rateRatio Threshold',
    '209':	'Time Offset Measurement',
    '210':	'Cumulative rateRatio Measurement',
    '211':	'Remove SRR',
    '212':	'Create SRR',
    '213':	'Update SRR',
    '214':	'Session Report',
    '215':	'SRR ID',
    '216':	'Access Availability Control Information',
    '217':	'Requested Access Availability Information',
    '218':	'Access Availability Report',
    '219':	'Access Availability Information',
    '220':	'Provide ATSSS Control Information',
    '221':	'ATSSS Control Parameters',
    '222':	'MPTCP Control Information',
    '223':	'ATSSS-LL Control Information',
    '224':	'PMF Control Information',
    '225':	'MPTCP Parameters',
    '226':	'ATSSS-LL Parameters',
    '227':	'PMF Parameters',
    '228':	'MPTCP Address Information',
    '229':	'UE Link-Specific IP Address',
    '230':	'PMF Address Information',
    '231':	'ATSSS-LL Information',
    '232':	'Data Network Access Identifier',
    '233':	'UE IP address Pool Information',
    '234':	'Average Packet Delay',
    '235':	'Minimum Packet Delay',
    '236':	'Maximum Packet Delay',
    '237':	'QoS Report Trigger',
    '238':	'GTP-U Path QoS Control Information',
    '239':	'GTP-U Path QoS Report (PFCP Node Report Request)',
    '240':	'QoS Information in GTP-U Path QoS Report',
    '241':	'GTP-U Path Interface Type',
    '242':	'QoS Monitoring per QoS flow Control Information',
    '243':	'Requested QoS Monitoring',
    '244':	'Reporting Frequency',
    '245':	'Packet Delay Thresholds',
    '246':	'Minimum Wait Time',
    '247':	'QoS Monitoring Report',
    '248':	'QoS Monitoring Measurement',
    '249':	'MT-EDT Control Information',
    '250':	'DL Data Packets Size',
    '251':	'QER Control Indications',
    '252':	'Packet Rate Status Report',
    '253':	'NF Instance ID',
    '254':	'Ethernet Context Information',
    '255':	'Redundant Transmission Parameters',
    '256':	'Updated PDR'
}

# ------------------------------------------------------------

def getFromDict(dataDict, mapList):
    return reduce(operator.getitem, mapList, dataDict)

# ------------------------------------------------------------

def JsonInspector(data, field, path=[]):
    for key, value in data.items():
        path.append(key)
        if field == key:
            yield path
        if isinstance(value, dict):
            yield from JsonInspector(value, field, path)
        path.pop()

# ------------------------------------------------------------
# define function to remove 'per.' in keys
def JsonKeyRemover(data, fieldInKey):
    if isinstance(data, dict):
        for key in list(data.keys()):
            if fieldInKey in key:
                del data[key]
            else:
                JsonKeyRemover(data[key], fieldInKey)

# ------------------------------------------------------------


def pfcpAnalyzer(pkt, traceName):

    # connect to DB
    client = pymongo.MongoClient(connectionToMongo)
    db = client['traces_sequence_data']
    col = db['data']
    client.close()
    # data = col.find_one({"_id":2}, {"_id":0})

    packetNumber = str(pkt.number)

    data_pfcp_layer = dict(pkt.pfcp._all_fields)
    keysToRemove = ['pfcp.flags', 'pfcp.flags_tree', 'pfcp.length', 'pfcp.seid', 'pfcp.seqno','pfcp.mp', 'pfcp.spare_h0', 'pfcp.ie_len']
    for keys in keysToRemove:
        JsonKeyRemover(data_pfcp_layer, keys)
    msg_type = pkt.pfcp.msg_type
    msg_name = pfcp_messages.get(msg_type, {}).get('name', msg_type)
    
    main_line = {'text': 'PFCP {}'.format(msg_name), 'color': 'blue'}
    message_lines = [main_line]

    required = pfcp_messages.get(msg_type, {}).get('required', True)
    needFilter = pfcp_messages.get(msg_type, {}).get('filter', False)
    filterFields = pfcp_messages.get(msg_type, {}).get('fields', [])
    ShowOnMainLine = pfcp_messages.get(msg_type, {}).get('ShowOnMainLine', False)

    print('------------- PFCP: packet Number {ix}, MessageType: {iy}, MessageName: {iz} -------------'.format(ix=packetNumber, iy=msg_type, iz=msg_name))
    print('Is there any filter on parameters?  {ix}'.format(ix=needFilter))
    print('Is it requred?  {ix}'.format(ix=required))
    dataInSeq = {}
    FilteredDataInSeq = {}
    if required:
        for ListofKeys in JsonInspector(data_pfcp_layer, "pfcp.ie_type"):
            ie_type = getFromDict(data_pfcp_layer, ListofKeys)
            ie_name = pfcp_ie_types.get(ie_type, ie_type)
            element = getFromDict(data_pfcp_layer, ListofKeys[:-1])
            print('ie_type is: {ix} and ie_name is: {iy}'.format(ix = ie_type, iy = ie_name))
            dataInSeq[ie_name] = element
            
            if needFilter:
                if int(ie_type) in filterFields:
                    FilteredDataInSeq[ie_name] = element
                

    if ShowOnMainLine:
        if needFilter:
            DataToShow = FilteredDataInSeq
        else:
            DataToShow = dataInSeq
        if DataToShow:
            protocolData = json.dumps(DataToShow, indent=2)
            LinesOfData = protocolData.splitlines()
            for lines in LinesOfData:
                line_text = '{}'.format(lines)
                message_lines.append({'text': line_text})


    dataToMongo = {'name': traceName, 'packetNumber': packetNumber, 'data': dataInSeq}
    x = col.insert(dataToMongo, check_keys=False)
    client.close()
    return message_lines


