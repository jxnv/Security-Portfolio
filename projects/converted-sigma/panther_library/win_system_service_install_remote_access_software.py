# Title: Remote Access Tool Services Have Been Installed - System
# ID: 1a31b18a-f00c-4061-9900-f735b96c99fc
# Status: test
# Level: medium
# Author: Connor Martin, Nasreddine Bencherchali
# Date: 2022-12-23
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1543.003, attack.t1569.002
# Description: Detects service installation of different remote access tools software. These software are often abused by threat actors to perform
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote Access Tool Services Have Been Installed - System
def rule(event):
    # Detection Logic:
    # (Provider_Name="Service Control Manager" AND (EventID="7045" OR EventID="7036") AND (ServiceName="*AmmyyAdmin*" OR ServiceName="*Atera*" OR ServiceName="*BASupportExpressSrvcUpdater*" OR ServiceName="*BASupportExpressStandaloneService*" OR ServiceName="*chromoting*" OR ServiceName="*GoToAssist*" OR ServiceName="*GoToMyPC*" OR ServiceName="*jumpcloud*" OR ServiceName="*LMIGuardianSvc*" OR ServiceName="*LogMeIn*" OR ServiceName="*monblanking*" OR ServiceName="*Parsec*" OR ServiceName="*RManService*" OR ServiceName="*RPCPerformanceService*" OR ServiceName="*RPCService*" OR ServiceName="*SplashtopRemoteService*" OR ServiceName="*SSUService*" OR ServiceName="*TeamViewer*" OR ServiceName="*TightVNC*" OR ServiceName="*vncserver*" OR ServiceName="*Zoho*"))
    return True

def title(event):
    return "Remote Access Tool Services Have Been Installed - System"

