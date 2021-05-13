#!/home/vagrant/fiveGSequenceAnalyzer/.env/bin/python

import pyshark
import subprocess
import libs.pcap as pcap
import sys
import pymongo
# pcap_file_path = 'test_TestServiceRequest.pcap'
pcap_file_path = sys.argv[1]
# Run commands like below
# sudo python3 main.py TraceFiles/test_TestServiceRequest.pcap


connectionToMongo = 'mongodb://localhost:27017/'


# Connect to DB to fetch data
client = pymongo.MongoClient(connectionToMongo)
db = client['diagram']

# ----------------------------- puml options ---------------------------------- #
colPuml = db["puml"]

queryData = colPuml.find_one({"_id": 2}, {"_id": 0, "nodealias": 1})
string = '{'
for element in queryData.get('nodealias', []):
        option = element.get('option')
        string = string + option + ','
        
string = string + '}'
nodealiases = eval(string)


queryData = colPuml.find_one({"_id": 2}, {"_id": 0, "graph": 1})
puml_start_options = []
for element in queryData.get('graph', []):
        option = element.get('option').replace("'", "")
        puml_start_options.append(option)

puml_start_options.append('')   


# nodealiases = {
#         '127.0.0.1:29502': 'SMF',
#         '127.0.0.1:29503': 'UDM',
#         '127.0.0.1:29504': 'UDR',
#         '127.0.0.1:29507': 'PCF',
#         '127.0.0.1:29509': 'AUSF',
#         '127.0.0.1:29518': 'AMF', 
#         '127.0.0.1:38412': 'AMF',
#         '127.0.0.1:9487': 'gNB',
#         '10.200.200.1:8805': 'SMF',
#         '10.200.200.101:8805': 'UPF',
#         }

# PlantUML options at start of .puml file
# refer to "https://plantuml.com/sequence-diagram" for more options
# puml_start_options = [
#         'scale 0.9',
#         'skinparam svgDimensionStyle false',
#         'skinparam sequenceArrowThickness 2',
#         'skinparam roundcorner 20',
#         'actor User #red',
#         'participant gNB',
#         'participant AMF',
#         'participant SMF',
#         'collections 127.0.0.1',
#         'participant AUSF',
#         'participant UDM',
#         'participant UDR',
#         'participant PCF',
#         'participant UPF',
#         '',
#         ]



# ----------------------------- wireshark options ---------------------------------- #
colWireshark = db["wireshark"]


# display_filter
queryData = colWireshark.find_one({"_id": 2}, {"_id": 0, "filters": 1})
display_filter = ''
for element in queryData.get('filters', []):
        option = element.get('option').replace("'", " ")
        display_filter = display_filter + option


# decodeas
queryData = colWireshark.find_one({"_id": 2}, {"_id": 0, "decoders": 1})
string = '{'
for element in queryData.get('decoders', []):
        option = element.get('option')
        string = string + option + ','
        
string = string + '}'
decodeas = eval(string)


# protocols
queryData = colWireshark.find_one({"_id": 2}, {"_id": 0, "protocols": 1})
protocols = []
for element in queryData.get('protocols', []):
        option = element.get('option')
        protocols.append(option)



# display_filter = '''
# tcp.port == 29502 or
# tcp.port == 29503 or
# tcp.port == 29504 or
# tcp.port == 29507 or
# tcp.port == 29509 or
# tcp.port == 29518 or
# tcp.port == 29510 or
# ngap or 
# pfcp
# '''


# decodeas = {'tcp.port==29502':'http2', 
#             'tcp.port==29503':'http2',
#             'tcp.port==29504':'http2',
#             'tcp.port==29507':'http2',
#             'tcp.port==29509':'http2',
#             'tcp.port==29518':'http2'
#             }


# protocols = [
#         'http2',
#         'pfcp',
#         'ngap',
#         ]



fiveG = pcap.fiveGTemplate(nodealiases=nodealiases)

packets = pyshark.FileCapture(pcap_file_path,display_filter=display_filter ,decode_as=decodeas, use_json=True, only_summaries=False)
# packets = pyshark.FileCapture(pcap_file_path,display_filter=display_filter ,decode_as=decodeas, use_json=True)
traceName = pcap_file_path.split('/')[-1].split('.')[0]
seq_diagram = fiveG.create_puml_seq_diagram(packets, protocols, traceName)


print(seq_diagram)

output_puml_file = pcap_file_path.split('.')[0] + '.puml'
output_svg_file = pcap_file_path.split('.')[0] + '.svg'
#this should be in a try except block. Not changing in case author wants to keep as is
with open(output_puml_file, 'w') as puml_file:
    puml_file.write('\n'.join(seq_diagram.get_puml_lines(puml_start_options)))
    #puml_file.close()           #---> In previous verion, file was open and I received error 'no image found' so I had to add close.
    # command = 'java -jar plantuml.jar -verbose ' + output_puml_file
# below commands are not needed in the with block. It is better to isolate them

command = 'java -jar plantuml.jar -tsvg -verbose ' + output_puml_file
print('Wrote PUML output to ' + output_puml_file)
child = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
is_error = False
for line in child.stderr:
print(line)
is_error = True

if(not is_error):
output_svg_file = pcap_file_path + '.svg'
print('Wrote PNG output to ' + output_svg_file)
print('Displaying ' + output_svg_file)
