# Title: Windows Filtering Platform Blocked Connection From EDR Agent Binary
# ID: bacf58c6-e199-4040-a94f-95dea0f1e45a
# Status: test
# Level: high
# Author: @gott_cyber
# Date: 2024-01-08
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects a Windows Filtering Platform (WFP) blocked connection event involving common Endpoint Detection and Response (EDR) agents.
# Adversaries may use WFP filters to prevent Endpoint Detection and Response (EDR) agents from reporting security events.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Filtering Platform Blocked Connection From EDR Agent Binary
def rule(event):
    # Detection Logic:
    # (EventID="5157" AND (Application="*\\AmSvc.exe" OR Application="*\\cb.exe" OR Application="*\\CETASvc.exe" OR Application="*\\CNTAoSMgr.exe" OR Application="*\\CrAmTray.exe" OR Application="*\\CrsSvc.exe" OR Application="*\\CSFalconContainer.exe" OR Application="*\\CSFalconService.exe" OR Application="*\\CybereasonAV.exe" OR Application="*\\CylanceSvc.exe" OR Application="*\\cyserver.exe" OR Application="*\\CyveraService.exe" OR Application="*\\CyvrFsFlt.exe" OR Application="*\\EIConnector.exe" OR Application="*\\elastic-agent.exe" OR Application="*\\elastic-endpoint.exe" OR Application="*\\EndpointBasecamp.exe" OR Application="*\\ExecutionPreventionSvc.exe" OR Application="*\\filebeat.exe" OR Application="*\\fortiedr.exe" OR Application="*\\hmpalert.exe" OR Application="*\\hurukai.exe" OR Application="*\\LogProcessorService.exe" OR Application="*\\mcsagent.exe" OR Application="*\\mcsclient.exe" OR Application="*\\MsMpEng.exe" OR Application="*\\MsSense.exe" OR Application="*\\Ntrtscan.exe" OR Application="*\\PccNTMon.exe" OR Application="*\\QualysAgent.exe" OR Application="*\\RepMgr.exe" OR Application="*\\RepUtils.exe" OR Application="*\\RepUx.exe" OR Application="*\\RepWAV.exe" OR Application="*\\RepWSC.exe" OR Application="*\\sedservice.exe" OR Application="*\\SenseCncProxy.exe" OR Application="*\\SenseIR.exe" OR Application="*\\SenseNdr.exe" OR Application="*\\SenseSampleUploader.exe" OR Application="*\\SentinelAgent.exe" OR Application="*\\SentinelAgentWorker.exe" OR Application="*\\SentinelBrowserNativeHost.exe" OR Application="*\\SentinelHelperService.exe" OR Application="*\\SentinelServiceHost.exe" OR Application="*\\SentinelStaticEngine.exe" OR Application="*\\SentinelStaticEngineScanner.exe" OR Application="*\\sfc.exe" OR Application="*\\sophos ui.exe" OR Application="*\\sophosfilescanner.exe" OR Application="*\\sophosfs.exe" OR Application="*\\sophoshealth.exe" OR Application="*\\sophosips.exe" OR Application="*\\sophosLivequeryservice.exe" OR Application="*\\sophosnetfilter.exe" OR Application="*\\sophosntpservice.exe" OR Application="*\\sophososquery.exe" OR Application="*\\sspservice.exe" OR Application="*\\TaniumClient.exe" OR Application="*\\TaniumCX.exe" OR Application="*\\TaniumDetectEngine.exe" OR Application="*\\TMBMSRV.exe" OR Application="*\\TmCCSF.exe" OR Application="*\\TmListen.exe" OR Application="*\\TmWSCSvc.exe" OR Application="*\\Traps.exe" OR Application="*\\winlogbeat.exe" OR Application="*\\WSCommunicator.exe" OR Application="*\\xagt.exe"))
    return True

def title(event):
    return "Windows Filtering Platform Blocked Connection From EDR Agent Binary"

