
from django import forms
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
import pymongo



connectionToMongo = 'mongodb://localhost:27017/'

# Diagram Form
class diagramForm(forms.Form):
    diagram_graph_optionCount = forms.CharField(widget=forms.HiddenInput())
    diagram_graph_optionCountDefault = forms.CharField(widget=forms.HiddenInput())
    diagram_nodealias_optionCount = forms.CharField(widget=forms.HiddenInput())
    diagram_nodealias_optionCountDefault = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super(diagramForm, self).__init__(*args, **kwargs)
        myclient = pymongo.MongoClient(connectionToMongo)
        mydb = myclient['diagram']
        mycol = mydb["puml"]

        result = mycol.find_one({"_id":2}, {"_id":0})
        resultForDefaults = mycol.find_one({"_id":1}, {"_id":0})
        # --- Start of Graph --- #
        NumOfGraphOptions = len(result['graph'])
        self.fields['diagram_graph_optionCount'].initial = NumOfGraphOptions - 1
        self.fields['diagram_graph_optionCount'].widget.attrs['class'] = 'invisible'
        self.fields['diagram_graph_optionCount'].widget.attrs['default'] = NumOfGraphOptions - 1

        for i in range(0, NumOfGraphOptions):
            self.fields['diagram_graph_options-{i}'.format(i=i)] = forms.CharField(required=False, label="Option", widget=forms.TextInput(attrs={'class': "", 'id': 'diagram_graphOptionElement-{i}'.format(i=i)}))
            self.fields['diagram_graph_options-{i}'.format(i=i)].initial = result['graph'][i]['option']

        self.fields['diagram_graph_optionCountDefault'].initial = len(resultForDefaults['graph']) - 1
        
        # --- End of Graph --- #


        # --- Start of NodeAlias --- #

        NumOfnodealiasOptions = len(result['nodealias'])
        self.fields['diagram_nodealias_optionCount'].initial = NumOfnodealiasOptions - 1
        self.fields['diagram_nodealias_optionCount'].widget.attrs['class'] = 'invisible'
        self.fields['diagram_nodealias_optionCount'].widget.attrs['default'] = NumOfnodealiasOptions - 1

        for i in range(0, NumOfnodealiasOptions):
            self.fields['diagram_nodealias_options-{i}'.format(i=i)] = forms.CharField(required=False, label="Option", widget=forms.TextInput(attrs={'class': "", 'id': 'diagram_nodealiasOptionElement-{i}'.format(i=i)}))
            self.fields['diagram_nodealias_options-{i}'.format(i=i)].initial = result['nodealias'][i]['option']

        self.fields['diagram_nodealias_optionCountDefault'].initial = len(resultForDefaults['nodealias']) - 1
        # --- End of NodeAlias --- #

    def Hidden(self):
        return [field for field in self if field.name in ('diagram_graph_optionCount', 'diagram_graph_optionCountDefault', 'diagram_nodealias_optionCount', 'diagram_nodealias_optionCountDefault')]

    def Graph(self):
        return [field for field in self if 'diagram_graph_options' in field.name]

    def NodeAlias(self):
        return [field for field in self if 'diagram_nodealias_options' in field.name]


# Wireshark Form
class wiresharkForm(forms.Form):
    wireshark_protocols_optionCount = forms.CharField(widget=forms.HiddenInput())
    wireshark_protocols_optionCountDefault = forms.CharField(widget=forms.HiddenInput())
    wireshark_decoders_optionCount = forms.CharField(widget=forms.HiddenInput())
    wireshark_decoders_optionCountDefault = forms.CharField(widget=forms.HiddenInput())
    wireshark_filters_optionCount = forms.CharField(widget=forms.HiddenInput())
    wireshark_filters_optionCountDefault = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super(wiresharkForm, self).__init__(*args, **kwargs)
        myclient = pymongo.MongoClient(connectionToMongo)
        mydb = myclient['diagram']
        mycol = mydb["wireshark"]

        result = mycol.find_one({"_id":2}, {"_id":0})
        resultForDefaults = mycol.find_one({"_id":1}, {"_id":0})
        # --- Start of Protocols --- #
        NumOfProtocolOptions = len(result['protocols'])
        self.fields['wireshark_protocols_optionCount'].initial = NumOfProtocolOptions - 1
        self.fields['wireshark_protocols_optionCountDefault'].initial = len(resultForDefaults['protocols']) - 1

        
        self.fields['wireshark_protocols_optionCount'].widget.attrs['class'] = 'invisible'
        self.fields['wireshark_protocols_optionCount'].widget.attrs['default'] = NumOfProtocolOptions - 1

        for i in range(0, NumOfProtocolOptions):
            self.fields['wireshark_protocols_options-{i}'.format(i=i)] = forms.CharField(required=False, label="Protocol", widget=forms.TextInput(attrs={'class': "", 'id': 'wireshark_protocolsOptionElement-{i}'.format(i=i)}))
            self.fields['wireshark_protocols_options-{i}'.format(i=i)].initial = result['protocols'][i]['option']
        # --- End of Protocols --- #


        # --- Start of Decoders --- #
        NumOfdecodersOptions = len(result['decoders'])
        self.fields['wireshark_decoders_optionCount'].initial = NumOfdecodersOptions - 1
        self.fields['wireshark_decoders_optionCountDefault'].initial = len(resultForDefaults['decoders']) - 1

        
        self.fields['wireshark_decoders_optionCount'].widget.attrs['class'] = 'invisible'
        self.fields['wireshark_decoders_optionCount'].widget.attrs['default'] = NumOfdecodersOptions - 1

        for i in range(0, NumOfdecodersOptions):
            self.fields['wireshark_decoders_options-{i}'.format(i=i)] = forms.CharField(required=False, label="Decoder", widget=forms.TextInput(attrs={'class': "", 'id': 'wireshark_decodersOptionElement-{i}'.format(i=i)}))
            self.fields['wireshark_decoders_options-{i}'.format(i=i)].initial = result['decoders'][i]['option']
        # --- End of Decoders --- #

        
        # --- Start of filters --- #
        NumOffiltersOptions = len(result['filters'])
        self.fields['wireshark_filters_optionCount'].initial = NumOffiltersOptions - 1
        self.fields['wireshark_filters_optionCountDefault'].initial = len(resultForDefaults['filters']) - 1
        self.fields['wireshark_filters_optionCount'].widget.attrs['class'] = 'invisible'
        self.fields['wireshark_filters_optionCount'].widget.attrs['default'] = NumOffiltersOptions - 1

        for i in range(0, NumOffiltersOptions):
            self.fields['wireshark_filters_options-{i}'.format(i=i)] = forms.CharField(required=False, label="Filter", widget=forms.TextInput(attrs={'class': "", 'id': 'wireshark_filtersOptionElement-{i}'.format(i=i)}))
            self.fields['wireshark_filters_options-{i}'.format(i=i)].initial = result['filters'][i]['option']
        # --- End of filters --- #



    def Hidden(self):
        return [field for field in self if field.name in ('wireshark_protocols_optionCount', 'wireshark_decoders_optionCount', 'wireshark_filters_optionCount', 'wireshark_protocols_optionCountDefault', 'wireshark_decoders_optionCountDefault', 'wireshark_filters_optionCountDefault')]

    def Protocols(self):
        return [field for field in self if 'wireshark_protocols_options' in field.name]

    def Decoders(self):
        return [field for field in self if 'wireshark_decoders_options' in field.name]

    def Filters(self):
        return [field for field in self if 'wireshark_filters_options' in field.name]


# Http2 Form
class http2Form(forms.Form):

    def __init__(self, *args, **kwargs):
        super(http2Form, self).__init__(*args, **kwargs)
        myclient = pymongo.MongoClient(connectionToMongo)
        mydb = myclient['diagram']
        mycol = mydb["http2Form"]

        result = mycol.find_one({"_id":2}, {"_id":0})

        # --- Start of Header --- #
        self.fields['diagram_http2_header_filter'] = forms.CharField(required=False, label="filter", widget=forms.TextInput(attrs={'class': ""}))
        self.fields['diagram_http2_header_filter'].initial = result['header']['filter']
        self.fields['diagram_http2_header_fields'] = forms.CharField(required=False, label="fields", widget=forms.TextInput(attrs={'class': ""}))
        self.fields['diagram_http2_header_fields'].initial = result['header']['fields']
        self.fields['diagram_http2_header_show'] = forms.CharField(required=False, label="show", widget=forms.TextInput(attrs={'class': ""}))
        self.fields['diagram_http2_header_show'].initial = result['header']['ShowOnMainLine']
        # --- End of Header --- #


        # --- Start of Payload --- #
        self.fields['diagram_http2_payload_filter'] = forms.CharField(required=False, label="filter", widget=forms.TextInput(attrs={'class': ""}))
        self.fields['diagram_http2_payload_filter'].initial = result['payload']['filter']
        self.fields['diagram_http2_payload_fields'] = forms.CharField(required=False, label="fields", widget=forms.TextInput(attrs={'class': ""}))
        self.fields['diagram_http2_payload_fields'].initial = result['payload']['fields']
        self.fields['diagram_http2_payload_show'] = forms.CharField(required=False, label="show", widget=forms.TextInput(attrs={'class': ""}))
        self.fields['diagram_http2_payload_show'].initial = result['payload']['ShowOnMainLine']
        # --- End of Payload --- #

    def Header(self):
        return [field for field in self if 'diagram_http2_header' in field.name]
    
    def Payload(self):
        return [field for field in self if 'diagram_http2_payload' in field.name]



# class pfcpForm(forms.Form):
    
#     def __init__(self, *args, **kwargs):
#         super(pfcpForm, self).__init__(*args, **kwargs)
#         client = pymongo.MongoClient(connectionToMongo)
#         db = client['diagram']
#         col = db["pfcpForm"]
        
#         result = col.find_one({"_id":2}, {"_id":0})
#         pfcp_messages = result['pfcp_messages']
#         NumOfProtocolPfcp = len(result['pfcp_messages'])
#         # for i in range(0, NumOfProtocolPfcp):
#         #     self.fields['pfcp_protocol_msg_name-{i}'.format(i=i)] = forms.CharField(required=False, label="msg", widget=forms.TextInput(attrs={'class': ""}))
#         #     self.fields['pfcp_protocol_msg_name-{i}'.format(i=i)].initial = result['pfcp_messages']
        
#         i = 1
#         keys = pfcp_messages.keys()
#         for key in keys:
#             self.fields['pfcp_protocol_msg_id_{i}'.format(i=i)] = forms.CharField(required=False, label="IE", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['pfcp_protocol_msg_id_{i}'.format(i=i)].initial = key      
#             self.fields['pfcp_protocol_msg_name_{i}'.format(i=i)] = forms.CharField(required=False, label="msg", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['pfcp_protocol_msg_name_{i}'.format(i=i)].initial = pfcp_messages.get(key).get('name')
#             self.fields['pfcp_protocol_msg_required_{i}'.format(i=i)] = forms.BooleanField(required=False, label="required", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['pfcp_protocol_msg_required_{i}'.format(i=i)].initial = pfcp_messages.get(key).get('required')
#             self.fields['pfcp_protocol_msg_ShowOnMainLine_{i}'.format(i=i)] = forms.BooleanField(required=False, label="show", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['pfcp_protocol_msg_ShowOnMainLine_{i}'.format(i=i)].initial = pfcp_messages.get(key).get('ShowOnMainLine')
#             self.fields['pfcp_protocol_msg_filter_{i}'.format(i=i)] = forms.BooleanField(required=False, label="filter", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['pfcp_protocol_msg_filter_{i}'.format(i=i)].initial = pfcp_messages.get(key).get('filter')
#             self.fields['pfcp_protocol_msg_fields_{i}'.format(i=i)] = forms.CharField(required=False, label="fields", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['pfcp_protocol_msg_fields_{i}'.format(i=i)].initial = pfcp_messages.get(key).get('fields')         
#             i = i + 1

#     def Protocols(self):
#         return [field for field in self if 'pfcp_protocol_msg' in field.name]
    


# ----------------------------------------------------------------------------

# class ngapForm(forms.Form):
    
#     def __init__(self, *args, **kwargs):
#         super(ngapForm, self).__init__(*args, **kwargs)
#         client = pymongo.MongoClient(connectionToMongo)
#         db = client['diagram']
#         col = db["ngapForm"]
        
#         result = col.find_one({"_id":1}, {"_id":0})
#         protocol_ie_ids = result['protocol_ie_ids']
#         NumOfProtocolNgap = len(result['protocol_ie_ids'])
        
#         i = 1
#         keys = protocol_ie_ids.keys()
#         for key in keys:
#             self.fields['ngap_protocol_ie_id_{i}'.format(i=i)] = forms.CharField(required=False, label="IE", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['ngap_protocol_ie_id_{i}'.format(i=i)].initial = key      
#             self.fields['ngap_protocol_ie_name_{i}'.format(i=i)] = forms.CharField(required=False, label="msg", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['ngap_protocol_ie_name_{i}'.format(i=i)].initial = protocol_ie_ids.get(key).get('name')
#             self.fields['ngap_protocol_ie_required_{i}'.format(i=i)] = forms.BooleanField(required=False, label="required", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['ngap_protocol_ie_required_{i}'.format(i=i)].initial = protocol_ie_ids.get(key).get('required')
#             self.fields['ngap_protocol_ie_ShowOnMainLine_{i}'.format(i=i)] = forms.BooleanField(required=False, label="show", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['ngap_protocol_ie_ShowOnMainLine_{i}'.format(i=i)].initial = protocol_ie_ids.get(key).get('ShowOnMainLine')
#             self.fields['ngap_protocol_ie_filter_{i}'.format(i=i)] = forms.BooleanField(required=False, label="filter", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['ngap_protocol_ie_filter_{i}'.format(i=i)].initial = protocol_ie_ids.get(key).get('filter')
#             self.fields['ngap_protocol_ie_fields_{i}'.format(i=i)] = forms.CharField(required=False, label="fields", widget=forms.TextInput(attrs={'class': ""}))
#             self.fields['ngap_protocol_ie_fields_{i}'.format(i=i)].initial = protocol_ie_ids.get(key).get('fields')         
#             i = i + 1

#     def Protocols(self):
#         return [field for field in self if 'ngap_protocol_ie' in field.name]
    