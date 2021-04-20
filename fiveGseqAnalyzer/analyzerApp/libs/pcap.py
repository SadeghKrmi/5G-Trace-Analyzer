from __future__ import print_function
try:
    import itertools.ifilter as filter
except ImportError:
    pass

try:
    import itertools.imap as map
except ImportError:
    pass


import sys
import codecs
from libs import puml
import json
from libs.pcapfunctions import pcapjsonfilter, pcapjsonfilterSingleParent
from copy import copy
import libs.ngap as ngap
import libs.pfcp as pfcp
import libs.http2 as http2





def has_layer(packet, layer_name):
    return layer_name in map(lambda layer: layer._layer_name, packet.layers)

# I've added this function to valudate if the packet has http2 and streamid == 3
# This is Only for http2
def has_layer_http2(packet):
    if('http2' in map(lambda layer: layer._layer_name, packet.layers)):
        try:
            status = packet.http2.stream.get('streamid','') == '3'
        except AttributeError:
            # In case of http2 with Magic, or Settings+Window_Update, there will be an error, as magic packets are all with streamid = 0, we can skip them
            status = False
            # print('http2 without streamid 3, Number is: ' + str(packet.number))

        return status
    
    else:
        return False


def has_layer_list(packet, layer_names):
    ''' layer_names is list of layers in this function provided by user
        this function will checl layer_names in packet, if any of them matched,
        it will return True to include packet in sequence diagram
    '''
    layers = map(lambda layer: layer._layer_name, packet.layers)
    return any(layer in layer_names for layer in layers)


def has_layer_lists(packet, layer_names):
    ''' layer_names is list of layers in this function provided by user
        this function will checl layer_names in packet, if any of them matched,
        it will return True to include packet in sequence diagram
        if http2 packet is request by user, only sreamid == 3 are included in
        sequence diagram and other streamid are excluded (control streamid)
    '''
    layers = list(map(lambda layer: layer._layer_name, packet.layers))
    if 'http2' in layer_names and 'http2' in layers:
        return has_layer_http2(packet)
    else:
        return any(layer in layer_names for layer in layers)


class fiveGTemplate(object):
    ''' This is 5G template for fiveGbackpack'''
    def __init__(self, nodealiases={}):
        self.nodealiases=nodealiases

    COLORS = ['red', 'blue', 'green', 'purple', 'brown', 'magenta', 'aqua', 'orange']

    # def get_message_color(self, packet)



    def participantid_to_participantname(self, participantid):
        participantname = self.nodealiases.get(participantid)
        if(participantname == None):
            # participantname = participantid           #---> Modify participant name to have only 127.0.0.1 if node does not exist in nodealiases
            try:
                participantname = participantid.split(":")[0]
            except:
                participantname = participantid
        return participantname



    def get_transport_ports(self, packet):
        if(has_layer(packet, 'udp')):
            t_layer = packet.udp
        elif (has_layer(packet, 'tcp')):
            t_layer = packet.tcp
        elif (has_layer(packet, 'sctp')):
            t_layer = packet.sctp
        else:
            raise ValueError('packet contains no transport layer')
        
        return (t_layer.srcport, t_layer.dstport)


    def get_participant_ids(self, packet):
        (srcip, dstip) = (packet.ip.src, packet.ip.dst)
        (srcport, dstport) = self.get_transport_ports(packet)
        return (srcip+':'+srcport, dstip+':'+dstport)


    def get_participants(self, packet):
        (src_id, dst_id) = self.get_participant_ids(packet)
        src = {'name': '"{}"'.format(self.participantid_to_participantname(src_id))}
        dst = {'name': '"{}"'.format(self.participantid_to_participantname(dst_id))}
        return (src, dst)


    def get_arrow(self, packet):
        arrow = {'head': '>', 'shaft': '-', 'color': 'blue'}
        return arrow

    def get_sequence_number(self, packet):
        return {'number': packet.number}

    def get_timestamp(self, packet):
        return packet.sniff_timestamp


    def get_message_lines(self, packet, traceName):
        '''some shits here'''
        layers = list(map(lambda layer: layer._layer_name, packet.layers))
        highest_layer = packet.highest_layer.lower()
        message_lines = []
        if 'http2' in layers:
            message_lines = http2.http2Anlayzer(packet, traceName)
        elif 'pfcp' in layers:
            message_lines = pfcp.pfcpAnalyzer(packet, traceName)
        elif 'ngap' in layers:
            message_lines = ngap.ngapAnalyzer(packet, traceName)
        else:
            message_lines.append({'text': 'other_layers'})
        # print(message_lines)
        return message_lines



    def packet_to_seqevents(self, packet, traceName):
        seqevent = puml.SeqEvent(
                self.get_participants(packet),
                self.get_message_lines(packet, traceName),
                arrow=self.get_arrow (packet),
                timestamp=self.get_timestamp(packet),
                sequence_number=self.get_sequence_number(packet),
                notes=None,
                event_type=puml.SEQEVENT_TYPE_MESSAGE)
        return [seqevent]



    def packets_to_seqevents(self, packets, protocols, traceName):
        seqevents = []
        #  supported_packets = filter(lambda packet: has_layer(packet, 'http2'), packets)        #---> This line is changed to below to filter http2 protocols only
        # supported_packets = filter(lambda packet: has_layer_http2(packet), packets)
        supported_packets = filter(lambda packet: has_layer_lists(packet, protocols), packets)
        for packet in supported_packets:
            for seqevent in self.packet_to_seqevents(packet, traceName):
                seqevents.append(seqevent)
        return seqevents



    def create_puml_seq_diagram(self, packets, protocols, traceName):
        seqevents = self.packets_to_seqevents(packets, protocols, traceName)
        participants = None
        return puml.SeqDiagram(seqevents, participants=participants)


    
