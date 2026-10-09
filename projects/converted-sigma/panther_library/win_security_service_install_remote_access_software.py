# Title: Remote Access Tool Services Have Been Installed - Security
# ID: c8b00925-926c-47e3-beea-298fd563728e
# Status: test
# Level: medium
# Author: Connor Martin, Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-12-23
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1543.003, attack.t1569.002
# Description: Detects service installation of different remote access tools software. These software are often abused by threat actors to perform
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote Access Tool Services Have Been Installed - Security
def rule(event):
    # Detection Logic:
    # (EventID="4697" AND (ServiceName="*AmmyyAdmin*" OR ServiceName="*AnyDesk*" OR ServiceName="*Atera*" OR ServiceName="*BASupportExpressSrvcUpdater*" OR ServiceName="*BASupportExpressStandaloneService*" OR ServiceName="*chromoting*" OR ServiceName="*GoToAssist*" OR ServiceName="*GoToMyPC*" OR ServiceName="*jumpcloud*" OR ServiceName="*LMIGuardianSvc*" OR ServiceName="*LogMeIn*" OR ServiceName="*monblanking*" OR ServiceName="*Parsec*" OR ServiceName="*RManService*" OR ServiceName="*RPCPerformanceService*" OR ServiceName="*RPCService*" OR ServiceName="*SplashtopRemoteService*" OR ServiceName="*SSUService*" OR ServiceName="*TeamViewer*" OR ServiceName="*TightVNC*" OR ServiceName="*vncserver*" OR ServiceName="*Zoho*"))
    return True

def title(event):
    return "Remote Access Tool Services Have Been Installed - Security"

