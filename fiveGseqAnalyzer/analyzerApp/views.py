from django.shortcuts import render
from django.views.generic import TemplateView, View
from .models import UploadedTracesModel, AnalyzerScenarioModel
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse
from django.forms.models import model_to_dict
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin

from django.views.static import serve 

from rest_framework.exceptions import ParseError
from rest_framework.parsers import FileUploadParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from pathlib import Path
from os import path, system, chdir

from datetime import datetime

import pymongo

from .multiform import MultiFormsView # this is a Mixin from github for Multi fom in a class View
from .forms import diagramForm, wiresharkForm, http2Form

# from .forms ngapForm, pfcpForm


connectionToMongo = 'mongodb://localhost:27017/'



class TraceView(LoginRequiredMixin, MultiFormsView):
    login_url = 'login'
    redirect_field_name = 'redirect_to'
    template_name = "analyzerApp/analyzerApp.html"

    # it is possible to remove "def get()" as well.
    form_classes  = {'diagramForm': diagramForm, 'wiresharkForm': wiresharkForm, 'http2Form': http2Form}

    def get_context_data(self, **kwargs):
        context = super(TraceView, self).get_context_data(**kwargs)
        allTraces = UploadedTracesModel.objects.order_by('-uploaded_at').all()
        records = len(allTraces)
        RecInPage = 5 # if change it here, change it in TraceUpdater as well
        paginator = Paginator(allTraces, RecInPage)
        page_ranges = paginator.page_range
        # page_number = request.GET.get('page')
        page_number = 1
        page_obj = paginator.get_page(page_number)
        # return render(request, self.template_name , {'page_obj': page_obj,'page_ranges': page_ranges, 'records': records})
        context.update({'page_obj': page_obj,'page_ranges': page_ranges, 'records': records})
        return context


class TraceAnalyzeView(APIView):
    parser_class = (FileUploadParser,)

    def post(self, request, format=None):
        if 'file' not in request.data:
            return Response(status=status.HTTP_400_BAD_REQUEST)


        NumOfTraces = UploadedTracesModel.objects.all().count()
        MaxPossibleTraces = 40

        fileData = request.data['file']
        timeTag = datetime.now().strftime("%Y%m%d%H%M%S")
        realFileName = fileData.name
        filename = realFileName.split('.')[0] + '-' + timeTag + '.' + realFileName.split('.')[1]


        if ( NumOfTraces < MaxPossibleTraces )  & ( filename.split('.')[-1] == "pcap" ):
            BASE_DIR = Path(__file__).resolve().parent.parent
            TRACEFILES_ROOT = path.join(BASE_DIR, "analyzerApp/traces/")

            destination = open(TRACEFILES_ROOT + filename, 'wb+')
            for chunk in fileData.chunks():
                destination.write(chunk)
            destination.close()
            result = runfiveGAnalyzer(filename)
            if result == 0:
                UploadedTracesModel.objects.create(TestName=filename, realFileName=realFileName, status='ok')
                # HTTP_201_CREATED: if the result is valud
                return Response(status=status.HTTP_201_CREATED)
            else:
                filenames = filename.split('.')[0]
                system("rm -f " + TRACEFILES_ROOT + filenames + "*") # to delete puml, pcal and svg files
                # HTTP_400_BAD_REQUEST: if the result is not valud
                return Response(status=status.HTTP_400_BAD_REQUEST)
        elif ( NumOfTraces >= MaxPossibleTraces )  & ( filename.split('.')[-1] == "pcap" ):
            # HTTP_404_NOT_FOUND : for reaching max allowed traces
            return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


def TraceUpdater(request):
    page_number = request.GET.get('page_number')
    allTraces = UploadedTracesModel.objects.order_by('-uploaded_at').all()
    records = len(allTraces)
    RecInPage = 5 # if change it here, change it in TraceView as well
    paginator = Paginator(allTraces, RecInPage)
    page_nums = paginator.num_pages
    page_obj = paginator.get_page(page_number)
    doc = []
    for element in  page_obj:
        # print(model_to_dict(element))
        doc.append(model_to_dict(element))
    data = {"status": True, "payload": doc, "records": records, "page_nums": page_nums}
    return JsonResponse(data)


def TraceDelete(request):
    TestName = request.GET.get('TestName')
    TestName = TestName[4:] # to remove del_ from first of id of li in html
    filenames = TestName.split('.')[0]
    BASE_DIR = Path(__file__).resolve().parent.parent
    TRACEFILES_ROOT = path.join(BASE_DIR, "analyzerApp/traces/")
    realFileName = UploadedTracesModel.objects.filter(TestName=TestName).values_list('realFileName', flat=True)
    realFileName = realFileName[0]
    try:
        UploadedTracesModel.objects.filter(TestName=TestName).delete()
        system("rm -f " + TRACEFILES_ROOT + filenames + "*") # to delete puml, pcal and svg files
        data = {"status": True, "error": realFileName + " is removed"}
    except:
        data = {"status": False, "error": "Unable to remove " + realFileName}
    return JsonResponse(data)


def loadTraceSVG(request):
    TestName = request.GET.get('TestName')
    fileName = TestName.split('.')[0] + ".svg"
    BASE_DIR = Path(__file__).resolve().parent.parent
    TRACEFILES_ROOT = path.join(BASE_DIR, "analyzerApp/traces/")
    imageFile = open(TRACEFILES_ROOT + fileName, "rb")

    response = HttpResponse(imageFile)
    # As response is not json, dataType: 'json' is commented in Ajax 
    return response


def downloadTrace(request):
    TestName = request.GET.get('TestName')
    TestName = TestName[9:] # to remove download_ from first of id of li in html
    downloadFilesPath = path.join(settings.BASE_DIR, 'analyzerApp/traces/')
    fileName = TestName
    fileContent = open(downloadFilesPath + fileName, 'rb')
    # response = HttpResponse(fileContent, content_type='application/force-download')
    # response['Content-Disposition'] = 'attachment; filename="{}"'.format(fileName)

    # return response


# ------------------------------ Start Of Analyzer Scenario ------------------------------

def analyzerScenario(request):
    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col_savedScenarios = db['savedScenarios']
    col_http2Form = db['http2Form']
    http2Val = col_http2Form.find_one({"_id": 2}, {"_id":0})
    col_ngapForm = db['ngapForm']
    ngapVal = col_ngapForm.find_one({"_id": 2}, {"_id":0})
    col_pfcpForm = db['pfcpForm']
    pfcpVal = col_pfcpForm.find_one({"_id": 2}, {"_id":0})
    col_puml = db['puml']
    pumlVal = col_puml.find_one({"_id": 2}, {"_id":0})
    col_wireshark = db['wireshark']
    wiresharkVal = col_wireshark.find_one({"_id": 2}, {"_id":0})
    
    # AnalyzerScenarioModel
    name = request.POST.get('name')
    description = request.POST.get('description')
    exist = AnalyzerScenarioModel.objects.filter(scenarioName__iexact = name)
    if exist:
        status = False
        msg = "Scenario name is duplicate"
        data = {"status": status, "msg": msg}
    else:
        status = True 
        msg = "New scenario " + name +" is added"
        record = AnalyzerScenarioModel.objects.create(scenarioName=name, scenarioDescription=description)
        scenarioId =  AnalyzerScenarioModel.objects.filter(scenarioName__iexact = name).values_list('id', flat=True)
        scenarioId = list(scenarioId)[0]
        print(scenarioId)
        x = col_savedScenarios.insert_one({"_id": scenarioId, "http2Form": http2Val, "ngapForm": ngapVal, "pfcpForm": pfcpVal, "puml": pumlVal, "wireshark": wiresharkVal})   

        data = {"status": status, "msg": msg, "scenarioId": scenarioId, "name": name, "description": description}
    client.close()
    return JsonResponse(data)


def analyzerScenarioLoader(request):
    allScenarios = AnalyzerScenarioModel.objects.all()
    doc = []
    for element in  allScenarios:
        doc.append(model_to_dict(element))

    data = {"status": True, "payload": doc}
    return JsonResponse(data)


def analyzerScenarioAction(request):
    action = request.POST.get('action')
    scenarioId = request.POST.get('scenarioId')
    scenarioName =  AnalyzerScenarioModel.objects.filter(id__iexact = int(scenarioId)).values_list('scenarioName', flat=True)
    scenarioName = list(scenarioName)[0]
    name = request.POST.get('name')

    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col_savedScenarios = db['savedScenarios']

    status = False
    msg = "Something went wrong!"    
    data = {"status": status, "msg": msg}

    if action == 'enable':
        ScenarioValues = col_savedScenarios.find_one({"_id": int(scenarioId)}, {"_id":0})

        col_http2Form = db['http2Form']
        http2Form = ScenarioValues['http2Form']
        x = col_http2Form.delete_one({"_id": 2})
        x = col_http2Form.insert_one({"_id": 2, "header": http2Form['header'], "payload": http2Form['payload']})
        
        col_ngapForm = db['ngapForm']
        ngapForm = ScenarioValues['ngapForm']
        x = col_ngapForm.delete_one({"_id": 2})
        x = col_ngapForm.insert_one({"_id": 2, "ProcedureCodes": ngapForm['ProcedureCodes']})

        col_pfcpForm = db['pfcpForm']
        pfcpForm = ScenarioValues['pfcpForm']
        x = col_pfcpForm.delete_one({"_id": 2})
        x = col_pfcpForm.insert_one({"_id": 2, "pfcp_messages": pfcpForm['pfcp_messages']})
        
        col_puml = db['puml']
        puml = ScenarioValues['puml']
        x = col_puml.delete_one({"_id": 2})
        x = col_puml.insert_one({"_id": 2, "graph": puml['graph'], "nodealias": puml['nodealias']})
        

        col_wireshark = db['wireshark']
        wireshark = ScenarioValues['wireshark']
        print(wireshark)
        x = col_wireshark.delete_one({"_id": 2})
        x = col_wireshark.insert_one({"_id": 2, "filters": wireshark['filters'], "decoders": wireshark['decoders'], "protocols": wireshark['protocols']})
        
        status = True
        msg = "Scenario " + scenarioName + " is enabled"
        data = {"status": status, "msg": msg}

    elif action == 'delete':
        x = col_savedScenarios.delete_one({"_id": int(scenarioId)})
        AnalyzerScenarioModel.objects.filter(id=int(scenarioId)).delete()
        status = True
        msg = "Scenario " + scenarioName + " is deleted"
        data = {"status": status, "msg": msg}

    client.close()
    return JsonResponse(data)

# ------------------------------ Start Of Analyzer Scenario ------------------------------

def http2Updater(request):
    PressedButton = request.POST.get('PressedButton')

    myclient = pymongo.MongoClient(connectionToMongo)
    mydb = myclient['diagram']
    mycol = mydb["http2Form"]    

    queryDict = request.POST.dict()
    keysInData = queryDict.keys()

    # Header
    header_filter = eval(request.POST.get('diagram_http2_header_filter'))
    header_fields = eval(request.POST.get('diagram_http2_header_fields'))
    header_show = eval(request.POST.get('diagram_http2_header_show'))

    header = {'filter': header_filter, 'fields': header_fields, 'ShowOnMainLine': header_show}

    # Payload
    payload_filter = eval(request.POST.get('diagram_http2_payload_filter'))
    payload_fields = eval(request.POST.get('diagram_http2_payload_fields'))
    payload_show = eval(request.POST.get('diagram_http2_payload_show'))

    payload = {'filter': payload_filter, 'fields': payload_fields, 'ShowOnMainLine': payload_show}


    # # To rewrite default configuration _id: 1
    # x = mycol.delete_one({"_id": 1})
    # x = mycol.insert_one({"_id": 1,  "header": header, "payload": payload})

    # to configure default_config http2
    # x = mycol.delete_one({"_id": "http2"})
    # queryDict["_id"] = "http2"
    # mycol.insert_one(queryDict)


    if PressedButton == 'Submit':

        x = mycol.delete_one({"_id": 2})
        x = mycol.insert_one({"_id": 2, "header": header, "payload": payload})    
        data = request.POST.dict()
    elif PressedButton == 'Reset':
        x = mycol.delete_one({"_id": 2})
        defaultValues = mycol.find_one({"_id": 1}, {"_id":0})
        print(defaultValues)
        x = mycol.insert_one({"_id": 2, "header": defaultValues['header'], "payload": defaultValues['payload']})
        data = mycol.find_one({"_id": "http2"}, {"PressedButton":0, "_id":0, "csrfmiddlewaretoken":0})

    myclient.close()
    # data = {}
    return JsonResponse(data)

# ------------------------------ End Of http2 ------------------------------


# ------------------------------ Start Of PFCP ------------------------------
def pfcpUpdater(request):
    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col = db["pfcpForm"]
    result = col.find_one({"_id":2}, {"_id":0})

    pfcp_messages = result['pfcp_messages']
    NumOfProtocolPFCP = len(result['pfcp_messages'])
    keys = pfcp_messages.keys()
    dataTotal = []
    for key in keys:
        reformatDict = {
            "id": int(key), 
            "name": pfcp_messages.get(key).get('name'), 
            "required": str(pfcp_messages.get(key).get('required')),
            "show": str(pfcp_messages.get(key).get('ShowOnMainLine')),
            "filter": str(pfcp_messages.get(key).get('filter')),
            "fields": pfcp_messages.get(key).get('fields'),
            }
        dataTotal.append(reformatDict)
    

    start = int(request.POST.get('start', None))
    length = int(request.POST.get('length', None))
    draw = int(request.POST.get('draw', None))
    search = request.POST.get('search[value]', None)
    
    FilteredData = dataTotal
    if len(search) != 0:
        FilteredData = []
        for item in dataTotal:
            if search in item['name'] or search in item['required'] or search in item['show'] or search in item['filter']:
                FilteredData.append(item)

        DataForTablePaginated = FilteredData[start:start+length]
        
    recordsTotal = len(dataTotal)
    recordsFiltered = len(FilteredData)
    DataForTablePaginated = FilteredData[start:start+length]
    data = {
        "draw": draw,
        "recordsTotal": recordsTotal,
        "recordsFiltered": recordsFiltered,
        "data": DataForTablePaginated
    }

    # data= {}
    client.close()
    return JsonResponse(data)


def pfcpEditor(request):
    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col = db["pfcpForm"]
    # result = col.find_one({"_id":2}, {"_id":0})

    IEid = request.POST.get('id')
    name = request.POST.get('name')
    required = eval(request.POST.get('required').capitalize())
    ShowOnMainLine = eval(request.POST.get('show').capitalize())
    filterX = eval(request.POST.get('filter').capitalize())
    fieldsX = request.POST.get('fields')

    if len(fieldsX) !=0 :
        fields = [int(x) for x in fieldsX.split(',')]

    else:
        fields = []
    dataToMongo = {
            "name": name,
            "required": required,
            "filter": filterX,
            "fields": fields,
            "ShowOnMainLine": ShowOnMainLine
        }
    data = {
            "id": int(IEid),
            "name": name,
            "required": required,
            "filter": filterX,
            "fields": fields,
            "show": ShowOnMainLine
        }

    result = col.update_one({"_id":2}, {'$set': {"pfcp_messages.{}".format(IEid): dataToMongo}})
    client.close()
    return JsonResponse(data)


def pfcpReset(request):
    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col = db["pfcpForm"]

    PressedButton = request.POST.get('PressedButton')

    defaultValues = col.find_one({"_id": 1}, {"_id":0})
    x = col.delete_one({"_id": 2})
    x = col.insert_one({"_id": 2, "pfcp_messages": defaultValues['pfcp_messages']})
    
    client.close()
    data = {}
    return JsonResponse(data)    

# ------------------------------ End Of PFCP ------------------------------


# ------------------------------ Start Of NGAP ------------------------------
def ngapUpdater(request):
    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col = db["ngapForm"]
    result = col.find_one({"_id":2}, {"_id":0})

    ProcedureCodes = result['ProcedureCodes']
    NumOfProtocolNgap = len(result['ProcedureCodes'])
    keys = ProcedureCodes.keys()
    dataTotal = []
    for key in keys:
        reformatDict = {
            "id": int(key), 
            "name": ProcedureCodes.get(key).get('name'), 
            "required": str(ProcedureCodes.get(key).get('required')),
            "show": str(ProcedureCodes.get(key).get('ShowOnMainLine')),
            "filter": str(ProcedureCodes.get(key).get('filter')),
            "fields": ProcedureCodes.get(key).get('fields'),
            }
        dataTotal.append(reformatDict)
    

    start = int(request.POST.get('start', None))
    length = int(request.POST.get('length', None))
    draw = int(request.POST.get('draw', None))
    search = request.POST.get('search[value]', None)
    
    FilteredData = dataTotal
    if len(search) != 0:
        FilteredData = []
        for item in dataTotal:
            if search in item['name'] or search in item['required'] or search in item['show'] or search in item['filter']:
                FilteredData.append(item)

        DataForTablePaginated = FilteredData[start:start+length]
        
    recordsTotal = len(dataTotal)
    recordsFiltered = len(FilteredData)
    DataForTablePaginated = FilteredData[start:start+length]
    data = {
        "draw": draw,
        "recordsTotal": recordsTotal,
        "recordsFiltered": recordsFiltered,
        "data": DataForTablePaginated
    }

    # data= {}
    client.close()
    return JsonResponse(data)


def ngapEditor(request):
    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col = db["ngapForm"]
    # result = col.find_one({"_id":2}, {"_id":0})

    IEid = request.POST.get('id')
    name = request.POST.get('name')
    required = eval(request.POST.get('required').capitalize())
    ShowOnMainLine = eval(request.POST.get('show').capitalize())
    filterX = eval(request.POST.get('filter').capitalize())
    fieldsX = request.POST.get('fields')
    
    if len(fieldsX) !=0 :
        fields = [int(x) for x in fieldsX.split(',')]
        print(fields)
    else:
        fields = []
    dataToMongo = {
            "name": name,
            "required": required,
            "filter": filterX,
            "fields": fields,
            "ShowOnMainLine": ShowOnMainLine
        }
    data = {
            "id": int(IEid),
            "name": name,
            "required": required,
            "filter": filterX,
            "fields": fields,
            "show": ShowOnMainLine
        }

    result = col.update_one({"_id":2}, {'$set': {"ProcedureCodes.{}".format(IEid): dataToMongo}})
    client.close()
    return JsonResponse(data)


def ngapReset(request):
    client = pymongo.MongoClient(connectionToMongo)
    db = client['diagram']
    col = db["ngapForm"]

    PressedButton = request.POST.get('PressedButton')

    defaultValues = col.find_one({"_id": 1}, {"_id":0})
    x = col.delete_one({"_id": 2})
    x = col.insert_one({"_id": 2, "ProcedureCodes": defaultValues['ProcedureCodes']})
    
    client.close()
    data = {}
    return JsonResponse(data)    
# ------------------------------ End Of NGAP ------------------------------

# puml sequence diagram options
def diagramUpdater(request):

    PressedButton = request.POST.get('PressedButton')

    queryDict = request.POST.dict()
    keysInData = queryDict.keys()

    diagram_graph_optionCount = len([x for x in keysInData if "diagram_graph_options" in x])
    graph = []
    for i in range(0, diagram_graph_optionCount):
        option = request.POST.get('diagram_graph_options-{ix}'.format(ix=i))
        graph.append({"option": option})


    diagram_nodealias_optionCount = len([x for x in keysInData if "diagram_nodealias_options" in x])
    nodealias = []
    for i in range(0, diagram_nodealias_optionCount):
        option = request.POST.get('diagram_nodealias_options-{ix}'.format(ix=i))
        nodealias.append({"option": option})


    myclient = pymongo.MongoClient(connectionToMongo)
    mydb = myclient['diagram']
    mycol = mydb["puml"]    

    # To rewrite default configuration _id: 1
    # x = mycol.delete_one({"_id": 1})
    # x = mycol.insert_one({"_id": 1, "graph": graph, "nodealias": nodealias})

    # to configure default_config puml
    # x = mycol.delete_one({"_id": "puml"})
    # queryDict["_id"] = "puml"
    # mycol.insert_one(queryDict)


    if PressedButton == 'Submit':

        x = mycol.delete_one({"_id": 2})
        x = mycol.insert_one({"_id": 2, "graph": graph, "nodealias": nodealias})    
        data = request.POST.dict()
    elif PressedButton == 'Reset':
        x = mycol.delete_one({"_id": 2})
        defaultValues = mycol.find_one({"_id": 1}, {"_id":0})
        x = mycol.insert_one({"_id": 2, "graph": defaultValues['graph'], "nodealias": defaultValues['nodealias']})
        data = mycol.find_one({"_id": "puml"}, {"PressedButton":0, "_id":0, "csrfmiddlewaretoken":0})
    
    myclient.close()
    return JsonResponse(data)


def wiresharkUpdater(request):
    
    PressedButton = request.POST.get('PressedButton')

    myclient = pymongo.MongoClient(connectionToMongo)
    mydb = myclient['diagram']
    mycol = mydb["wireshark"]

    queryDict = request.POST.dict()
    keysInData = queryDict.keys()



    wireshark_protocols_optionCount = len([x for x in keysInData if "wireshark_protocols_options" in x])
    protocols = []
    for i in range(0, wireshark_protocols_optionCount):
        option = request.POST.get('wireshark_protocols_options-{ix}'.format(ix=i))
        protocols.append({"option": option})
    

    wireshark_decoders_optionCount = len([x for x in keysInData if "wireshark_decoders_options" in x])
    decoders = []
    for i in range(0, wireshark_decoders_optionCount):
        option = request.POST.get('wireshark_decoders_options-{ix}'.format(ix=i))
        decoders.append({"option": option})


    wireshark_filters_optionCount = len([x for x in keysInData if "wireshark_filters_options" in x])
    filters = []
    for i in range(0, wireshark_filters_optionCount):
        option = request.POST.get('wireshark_filters_options-{ix}'.format(ix=i))
        filters.append({"option": option})


    # # To rewrite default configuration _id: 1
    # x = mycol.delete_one({"_id": 1})
    # x = mycol.insert_one({"_id": 1, "filters": filters, "decoders": decoders, "protocols": protocols})

    # to configure default_config wireshark
    # x = mycol.delete_one({"_id": "wireshark"})
    # queryDict["_id"] = "wireshark"
    # mycol.insert_one(queryDict)


    if PressedButton == 'Submit':

        x = mycol.delete_one({"_id": 2})
        x = mycol.insert_one({"_id": 2, "filters": filters, "decoders": decoders, "protocols": protocols})    
        data = request.POST.dict()

    elif PressedButton == 'Reset':
        x = mycol.delete_one({"_id": 2})
        defaultValues = mycol.find_one({"_id": 1}, {"_id":0})
        x = mycol.insert_one({"_id": 2, "filters": defaultValues['filters'], "decoders": defaultValues['decoders'], "protocols": defaultValues['protocols']})
        data = mycol.find_one({"_id": "wireshark"}, {"PressedButton":0, "_id":0, "csrfmiddlewaretoken":0})
    
    myclient.close()
    return JsonResponse(data)


def loadSeqLinkText(request):
    frameId = str(request.POST.get('id'))
    testName = request.POST.get('testName')
    client = pymongo.MongoClient(connectionToMongo)
    db = client['traces_sequence_data']
    col = db['data']

    data = col.find_one({'name': testName, 'packetNumber': frameId}, {"_id": 0})

    return JsonResponse(data)


def runfiveGAnalyzer(filename):
    BASE_DIR = Path(__file__).resolve().parent.parent
    TRACEFILES_ROOT = path.join(BASE_DIR, "analyzerApp/traces/")
    analyzerAppPath = path.join(BASE_DIR, "analyzerApp/")
    envpath =  path.join(BASE_DIR, "../.env/bin/")
    traceFileName = TRACEFILES_ROOT + filename
    print('processing file: ' + filename)
    chdir(analyzerAppPath)
    result = system('sudo timeout 120 '+envpath+ 'python3 main.py ' + traceFileName)
    
    return result