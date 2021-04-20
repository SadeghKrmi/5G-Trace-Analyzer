from libs.pcapfunctions import pcapjsonfilterSingleParent
import json
from functools import reduce
import operator
import pymongo


connectionToMongo = 'mongodb://localhost:27017/'

client = pymongo.MongoClient(connectionToMongo)
db = client['diagram']
col = db["ngapForm"]
result = col.find_one({"_id":2}, {"_id":0})
ProcedureCodes = result['ProcedureCodes']


# ProcedureCodes: NG Application Protocol!
# Ref: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/ngap/NGAP-Constants.asn
# ProcedureCodes = {
#         '0'  : {'name': 'id-AMFConfigurationUpdate', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '1'  : {'name': 'id-AMFStatusIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '2'  : {'name': 'id-CellTrafficTrace', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '3'  : {'name': 'id-DeactivateTrace', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '4'  : {'name': 'id-DownlinkNASTransport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '5'  : {'name': 'id-DownlinkNonUEAssociatedNRPPaTransport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '6'  : {'name': 'id-DownlinkRANConfigurationTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '7'  : {'name': 'id-DownlinkRANStatusTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '8'  : {'name': 'id-DownlinkUEAssociatedNRPPaTransport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '9'  : {'name': 'id-ErrorIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '10' : {'name': 'id-HandoverCancel', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '11' : {'name': 'id-HandoverNotification', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '12' : {'name': 'id-HandoverPreparation', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '13' : {'name': 'id-HandoverResourceAllocation', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '14' : {'name': 'id-InitialContextSetup', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '15' : {'name': 'id-InitialUEMessage', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '16' : {'name': 'id-LocationReportingControl', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '17' : {'name': 'id-LocationReportingFailureIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '18' : {'name': 'id-LocationReport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '19' : {'name': 'id-NASNonDeliveryIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '20' : {'name': 'id-NGReset', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '21' : {'name': 'id-NGSetup', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '22' : {'name': 'id-OverloadStart', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '23' : {'name': 'id-OverloadStop', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '24' : {'name': 'id-Paging', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '25' : {'name': 'id-PathSwitchRequest', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '26' : {'name': 'id-PDUSessionResourceModify', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '27' : {'name': 'id-PDUSessionResourceModifyIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '28' : {'name': 'id-PDUSessionResourceRelease', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '29' : {'name': 'id-PDUSessionResourceSetup', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '30' : {'name': 'id-PDUSessionResourceNotify', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '31' : {'name': 'id-PrivateMessage', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '32' : {'name': 'id-PWSCancel', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '33' : {'name': 'id-PWSFailureIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '34' : {'name': 'id-PWSRestartIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '35' : {'name': 'id-RANConfigurationUpdate', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '36' : {'name': 'id-RerouteNASRequest', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '37' : {'name': 'id-RRCInactiveTransitionReport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '38' : {'name': 'id-TraceFailureIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '39' : {'name': 'id-TraceStart', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '40' : {'name': 'id-UEContextModification', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '41' : {'name': 'id-UEContextRelease', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '42' : {'name': 'id-UEContextReleaseRequest', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '43' : {'name': 'id-UERadioCapabilityCheck', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '44' : {'name': 'id-UERadioCapabilityInfoIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '45' : {'name': 'id-UETNLABindingRelease', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '46' : {'name': 'id-UplinkNASTransport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '47' : {'name': 'id-UplinkNonUEAssociatedNRPPaTransport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '48' : {'name': 'id-UplinkRANConfigurationTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '49' : {'name': 'id-UplinkRANStatusTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '50' : {'name': 'id-UplinkUEAssociatedNRPPaTransport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '51' : {'name': 'id-WriteReplaceWarning', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '52' : {'name': 'id-SecondaryRATDataUsageReport', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '53' : {'name': 'id-UplinkRIMInformationTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '54' : {'name': 'id-DownlinkRIMInformationTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '55' : {'name': 'id-RetrieveUEInformation', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '56' : {'name': 'id-UEInformationTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '57' : {'name': 'id-RANCPRelocationIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '58' : {'name': 'id-UEContextResume', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '59' : {'name': 'id-UEContextSuspend', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '60' : {'name': 'id-UERadioCapabilityIDMapping', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '61' : {'name': 'id-HandoverSuccess', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '62' : {'name': 'id-UplinkRANEarlyStatusTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '63' : {'name': 'id-DownlinkRANEarlyStatusTransfer', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '64' : {'name': 'id-AMFCPRelocationIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#         '65' : {'name': 'id-ConnectionEstablishmentIndication', 'required': True, 'filter': False, 'fields': [], 'ShowOnMainLine': False},
#     }

# protocol_ie_ids: NG Application Protocol.
# Ref: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/ngap/NGAP-Constants.asn
protocol_ie_ids = {
        '0'  : 'AllowedNSSAI',
        '1'  : 'AMFName',
        '2'  : 'AMFOverloadResponse',
        '3'  : 'AMFSetID',
        '4'  : 'AMF-TNLAssociationFailedToSetupList',
        '5'  : 'AMF-TNLAssociationSetupList',
        '6'  : 'AMF-TNLAssociationToAddList',
        '7'  : 'AMF-TNLAssociationToRemoveList',
        '8'  : 'AMF-TNLAssociationToUpdateList',
        '9'  : 'AMFTrafficLoadReductionIndication',
        '10' : 'AMF-UE-NGAP-ID',
        '11' : 'AssistanceDataForPaging',
        '12' : 'BroadcastCancelledAreaList',
        '13' : 'BroadcastCompletedAreaList',
        '14' : 'CancelAllWarningMessages',
        '15' : 'Cause',
        '16' : 'CellIDListForRestart',
        '17' : 'ConcurrentWarningMessageInd',
        '18' : 'CoreNetworkAssistanceInformationForInactive',
        '19' : 'CriticalityDiagnostics',
        '20' : 'DataCodingScheme',
        '21' : 'DefaultPagingDRX',
        '22' : 'DirectForwardingPathAvailability',
        '23' : 'EmergencyAreaIDListForRestart',
        '24' : 'EmergencyFallbackIndicator',
        '25' : 'EUTRA-CGI',
        '26' : 'FiveG-S-TMSI',
        '27' : 'GlobalRANNodeID',
        '28' : 'GUAMI',
        '29' : 'HandoverType',
        '30' : 'IMSVoiceSupportIndicator',
        '31' : 'IndexToRFSP',
        '32' : 'InfoOnRecommendedCellsAndRANNodesForPaging',
        '33' : 'LocationReportingRequestType',
        '34' : 'MaskedIMEISV',
        '35' : 'MessageIdentifier',
        '36' : 'MobilityRestrictionList',
        '37' : 'NASC',
        '38' : 'NAS-PDU',
        '39' : 'NASSecurityParametersFromNGRAN',
        '40' : 'NewAMF-UE-NGAP-ID',
        '41' : 'NewSecurityContextInd',
        '42' : 'NGAP-Message',
        '43' : 'NGRAN-CGI',
        '44' : 'NGRANTraceID',
        '45' : 'NR-CGI',
        '46' : 'NRPPa-PDU',
        '47' : 'NumberOfBroadcastsRequested',
        '48' : 'OldAMF',
        '49' : 'OverloadStartNSSAIList',
        '50' : 'PagingDRX',
        '51' : 'PagingOrigin',
        '52' : 'PagingPriority',
        '53' : 'PDUSessionResourceAdmittedList',
        '54' : 'PDUSessionResourceFailedToModifyListModRes',
        '55' : 'PDUSessionResourceFailedToSetupListCxtRes',
        '56' : 'PDUSessionResourceFailedToSetupListHOAck',
        '57' : 'PDUSessionResourceFailedToSetupListPSReq',
        '58' : 'PDUSessionResourceFailedToSetupListSURes',
        '59' : 'PDUSessionResourceHandoverList',
        '60' : 'PDUSessionResourceListCxtRelCpl',
        '61' : 'PDUSessionResourceListHORqd',
        '62' : 'PDUSessionResourceModifyListModCfm',
        '63' : 'PDUSessionResourceModifyListModInd',
        '64' : 'PDUSessionResourceModifyListModReq',
        '65' : 'PDUSessionResourceModifyListModRes',
        '66' : 'PDUSessionResourceNotifyList',
        '67' : 'PDUSessionResourceReleasedListNot',
        '68' : 'PDUSessionResourceReleasedListPSAck',
        '69' : 'PDUSessionResourceReleasedListPSFail',
        '70' : 'PDUSessionResourceReleasedListRelRes',
        '71' : 'PDUSessionResourceSetupListCxtReq',
        '72' : 'PDUSessionResourceSetupListCxtRes',
        '73' : 'PDUSessionResourceSetupListHOReq',
        '74' : 'PDUSessionResourceSetupListSUReq',
        '75' : 'PDUSessionResourceSetupListSURes',
        '76' : 'PDUSessionResourceToBeSwitchedDLList',
        '77' : 'PDUSessionResourceSwitchedList',
        '78' : 'PDUSessionResourceToReleaseListHOCmd',
        '79' : 'PDUSessionResourceToReleaseListRelCmd',
        '80' : 'PLMNSupportList',
        '81' : 'PWSFailedCellIDList',
        '82' : 'RANNodeName',
        '83' : 'RANPagingPriority',
        '84' : 'RANStatusTransfer-TransparentContainer',
        '85' : 'RAN-UE-NGAP-ID',
        '86' : 'RelativeAMFCapacity',
        '87' : 'RepetitionPeriod',
        '88' : 'ResetType',
        '89' : 'RoutingID',
        '90' : 'RRCEstablishmentCause',
        '91' : 'RRCInactiveTransitionReportRequest',
        '92' : 'RRCState',
        '93' : 'SecurityContext',
        '94' : 'SecurityKey',
        '95' : 'SerialNumber',
        '96' : 'ServedGUAMIList',
        '97' : 'SliceSupportList',
        '98' : 'SONConfigurationTransferDL',
        '99' : 'SONConfigurationTransferUL',
        '100': 'SourceAMF-UE-NGAP-ID',
        '101': 'SourceToTarget-TransparentContainer',
        '102': 'SupportedTAList',
        '103': 'TAIListForPaging',
        '104': 'TAIListForRestart',
        '105': 'TargetID',
        '106': 'TargetToSource-TransparentContainer',
        '107': 'TimeToWait',
        '108': 'TraceActivation',
        '109': 'TraceCollectionEntityIPAddress',
        '110': 'UEAggregateMaximumBitRate',
        '111': 'UE-associatedLogicalNG-connectionList',
        '112': 'UEContextRequest',
        '113': 'Unknown-113',
        '114': 'UE-NGAP-IDs',
        '115': 'UEPagingIdentity',
        '116': 'UEPresenceInAreaOfInterestList',
        '117': 'UERadioCapability',
        '118': 'UERadioCapabilityForPaging',
        '119': 'UESecurityCapabilities',
        '120': 'UnavailableGUAMIList',
        '121': 'UserLocationInformation',
        '122': 'WarningAreaList',
        '123': 'WarningMessageContents',
        '124': 'WarningSecurityInfo',
        '125': 'WarningType',
        '126': 'AdditionalUL-NGU-UP-TNLInformation',
        '127': 'DataForwardingNotPossible',
        '128': 'DL-NGU-UP-TNLInformation',
        '129': 'NetworkInstance',
        '130': 'PDUSessionAggregateMaximumBitRate',
        '131': 'PDUSessionResourceFailedToModifyListModCfm',
        '132': 'PDUSessionResourceFailedToSetupListCxtFail',
        '133': 'PDUSessionResourceListCxtRelReq',
        '134': 'PDUSessionType',
        '135': 'QosFlowAddOrModifyRequestList',
        '136': 'QosFlowSetupRequestList',
        '137': 'QosFlowToReleaseList',
        '138': 'SecurityIndication',
        '139': 'UL-NGU-UP-TNLInformation',
        '140': 'UL-NGU-UP-TNLModifyList',
        '141': 'WarningAreaCoordinates',
        '142': 'PDUSessionResourceSecondaryRATUsageList',
        '143': 'HandoverFlag',
        '144': 'SecondaryRATUsageInformation',
        '145': 'PDUSessionResourceReleaseResponseTransfer',
        '146': 'RedirectionVoiceFallback',
        '147': 'UERetentionInformation',
        '148': 'S-NSSAI',
        '149': 'PSCellInformation',
        '150': 'LastEUTRAN-PLMNIdentity',
        '151': 'MaximumIntegrityProtectedDataRate-DL',
        '152': 'AdditionalDLForwardingUPTNLInformation',
        '153': 'AdditionalDLUPTNLInformationForHOList',
        '154': 'AdditionalNGU-UP-TNLInformation',
        '155': 'AdditionalDLQosFlowPerTNLInformation',
        '156': 'SecurityResult',
        '157': 'ENDC-SONConfigurationTransferDL',
        '158': 'ENDC-SONConfigurationTransferUL',
        '159': 'OldAssociatedQosFlowList-ULendmarkerexpected',
        '160': 'CNTypeRestrictionsForEquivalent',
        '161': 'CNTypeRestrictionsForServing',
        '162': 'NewGUAMI',
        '163': 'ULForwarding',
        '164': 'ULForwardingUP-TNLInformation',
        '165': 'CNAssistedRANTuning',
        '166': 'CommonNetworkInstance',
        '167': 'NGRAN-TNLAssociationToRemoveList',
        '168': 'TNLAssociationTransportLayerAddressNGRAN',
        '169': 'EndpointIPAddressAndPort',
        '170': 'LocationReportingAdditionalInfo',
        '171': 'SourceToTarget-AMFInformationReroute',
        '172': 'AdditionalULForwardingUPTNLInformation',
        '173': 'SCTP-TLAs',
        '174': 'SelectedPLMNIdentity',
        '175': 'RIMInformationTransfer',
        '176': 'GUAMIType',
        '177': 'SRVCCOperationPossible',
        '178': 'TargetRNC-ID',
        '179': 'RAT-Information',
        '180': 'ExtendedRATRestrictionInformation',
        '181': 'QosMonitoringRequest',
        '182': 'SgNB-UE-X2AP-ID',
        '183': 'AdditionalRedundantDL-NGU-UP-TNLInformation',
        '184': 'AdditionalRedundantDLQosFlowPerTNLInformation',
        '185': 'AdditionalRedundantNGU-UP-TNLInformation',
        '186': 'AdditionalRedundantUL-NGU-UP-TNLInformation',
        '187': 'CNPacketDelayBudgetDL',
        '188': 'CNPacketDelayBudgetUL',
        '189': 'ExtendedPacketDelayBudget',
        '190': 'RedundantCommonNetworkInstance',
        '191': 'RedundantDL-NGU-TNLInformationReused',
        '192': 'RedundantDL-NGU-UP-TNLInformation',
        '193': 'RedundantDLQosFlowPerTNLInformation',
        '194': 'RedundantQosFlowIndicator',
        '195': 'RedundantUL-NGU-UP-TNLInformation',
        '196': 'TSCTrafficCharacteristics',
        '197': 'RedundantPDUSessionInformation ',
        '198': 'UsedRSNInformation',
        '199': 'IAB-Authorized',
        '200': 'IAB-Supported',
        '201': 'IABNodeIndication',
        '202': 'NB-IoT-PagingDRX',
        '203': 'NB-IoT-Paging-eDRXInfo',
        '204': 'NB-IoT-DefaultPagingDRX',
        '205': 'Enhanced-CoverageRestriction',
        '206': 'Extended-ConnectedTime',
        '207': 'PagingAssisDataforCEcapabUE',
        '208': 'WUS-Assistance-Information',
        '209': 'UE-DifferentiationInfo',
        '210': 'NB-IoT-UEPriority',
        '211': 'UL-CP-SecurityInformation',
        '212': 'DL-CP-SecurityInformation',
        '213': 'TAI',
        '214': 'UERadioCapabilityForPagingOfNB-IoT',
        '215': 'LTEV2XServicesAuthorized',
        '216': 'NRV2XServicesAuthorized',
        '217': 'LTEUESidelinkAggregateMaximumBitrate',
        '218': 'NRUESidelinkAggregateMaximumBitrate',
        '219': 'PC5QoSParameters',
        '220': 'AlternativeQoSParaSetList',
        '221': 'CurrentQoSParaSetIndex',
        '222': 'CEmodeBrestricted',
        '223': 'PagingeDRXInformation',
        '224': 'CEmodeBSupport-Indicator',
        '225': 'LTEM-Indication',
        '226': 'EndIndication',
        '227': 'EDT-Session',
        '228': 'UECapabilityInfoRequest',
        '229': 'PDUSessionResourceFailedToResumeListRESReq',
        '230': 'PDUSessionResourceFailedToResumeListRESRes',
        '231': 'PDUSessionResourceSuspendListSUSReq',
        '232': 'PDUSessionResourceResumeListRESReq',
        '233': 'PDUSessionResourceResumeListRESRes',
        '234': 'UE-UP-CIoT-Support',
        '235': 'Suspend-Request-Indication',
        '236': 'Suspend-Response-Indication',
        '237': 'RRC-Resume-Cause',
        '238': 'RGLevelWirelineAccessCharacteristics',
        '239': 'W-AGFIdentityInformation',
        '240': 'GlobalTNGF-ID',
        '241': 'GlobalTWIF-ID',
        '242': 'GlobalW-AGF-ID',
        '243': 'UserLocationInformationW-AGF',
        '244': 'UserLocationInformationTNGF',
        '245': 'AuthenticatedIndication',
        '246': 'TNGFIdentityInformation',
        '247': 'TWIFIdentityInformation',
        '248': 'UserLocationInformationTWIF',
        '249': 'DataForwardingResponseERABList',
        '250': 'IntersystemSONConfigurationTransferDL',
        '251': 'IntersystemSONConfigurationTransferUL',
        '252': 'SONInformationReport',
        '253': 'UEHistoryInformationFromTheUE',
        '254': 'ManagementBasedMDTPLMNList',
        '255': 'MDTConfiguration',
        '256': 'PrivacyIndicator',
        '257': 'TraceCollectionEntityURI',
        '258': 'NPN-Support',
        '259': 'NPN-AccessInformation',
        '260': 'NPN-PagingAssistanceInformation',
        '261': 'NPN-MobilityInformation',
        '262': 'TargettoSource-Failure-TransparentContainer',
        '263': 'NID',
        '264': 'UERadioCapabilityID',
        '265': 'UERadioCapability-EUTRA-Format',
        '266': 'DAPSRequestInfo',
        '267': 'DAPSResponseInfoList',
        '268': 'EarlyStatusTransfer-TransparentContainer',
        '269': 'NotifySourceNGRANNode',
        '270': 'ExtendedSliceSupportList',
        '271': 'ExtendedTAISliceSupportList',
        '272': 'ConfiguredTACIndication',
        '273': 'Extended-RANNodeName',
        '274': 'Extended-AMFName',
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

def ngapAnalyzer(pkt, traceName):
    # connect to DB
    client = pymongo.MongoClient(connectionToMongo)
    db = client['traces_sequence_data']
    col = db['data']
    # data = col.find_one({"_id":2}, {"_id":0})

    packetNumber = str(pkt.number)

    data_ngap_layer = dict(pkt.ngap.NGAP_PDU_tree._all_fields)
    JsonKeyRemover(data_ngap_layer, "per.")

    KeyOfnameOfmessage = ''
    for ListofKeys in JsonInspector(data_ngap_layer, "ngap.procedureCode"):
        procedureCode = getFromDict(data_ngap_layer, ListofKeys)
        procedure_mgs = ProcedureCodes.get(procedureCode, procedureCode).get('name', 'procedureCode is {}'.format(procedureCode))
        NameOfmessage = getFromDict(data_ngap_layer, ListofKeys[:-1]).get('ngap.value_element')
        try:
            KeyOfnameOfmessage = list(NameOfmessage.keys())[0]
            KeyOfnameOfmessage = KeyOfnameOfmessage.split('ngap.')[1].split('_element')[0]
        except:
            pass
    
    if KeyOfnameOfmessage != '':
        procedure_mgs = KeyOfnameOfmessage
    
    main_line = {'text': 'NGAP {}'.format(procedure_mgs), 'color': 'blue'}
    message_lines = [main_line]

    ProtocolIE_Field_elements = []
    for ListofKeys in JsonInspector(data_ngap_layer, "ngap.ProtocolIE_Field_element"):
        ProtocolIE_Field_elements.append(getFromDict(data_ngap_layer, ListofKeys))


    required = ProcedureCodes.get(procedureCode, {}).get('required', True)
    needFilter = ProcedureCodes.get(procedureCode, {}).get('filter', False)
    filterFields = ProcedureCodes.get(procedureCode, {}).get('fields', [])
    ShowOnMainLine = ProcedureCodes.get(procedureCode, {}).get('ShowOnMainLine', False)

    print('------------- NGAP: packet Number {ix}, procedureCode: {iy}, procedure_mgs: {iz} -------------'.format(ix=packetNumber, iy=procedureCode, iz=procedure_mgs))
    print('Is there any filter on parameters?  {ix}'.format(ix=needFilter))
    print('Is it requred?  {ix}'.format(ix=required))
    print('show on main line?  {ix}'.format(ix=ShowOnMainLine))
    
    dataInSeq = {}
    FilteredDataInSeq = {}
    if required:
        for element in ProtocolIE_Field_elements:
            ngap_id = element.get("ngap.id")
            ngap_criticality = element.get("ngap.criticality")
            protocolIEName = protocol_ie_ids.get(ngap_id, {})
            print('ngap_id is: {ix} and protocolIEName is: {iy}'.format(ix = ngap_id, iy = protocolIEName))
            dataInSeq[protocolIEName] = element

            if needFilter:
                if int(ngap_id) in filterFields:
                    FilteredDataInSeq[protocolIEName] = element

    
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