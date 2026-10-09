// Title: Remote Access Tool Services Have Been Installed - Security
// ID: c8b00925-926c-47e3-beea-298fd563728e
// Status: test
// Level: medium
// Author: Connor Martin, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-23
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1543.003, attack.t1569.002
// Description: Detects service installation of different remote access tools software. These software are often abused by threat actors to perform
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID == "4697" AND (ServiceName contains "AmmyyAdmin" OR ServiceName contains "AnyDesk" OR ServiceName contains "Atera" OR ServiceName contains "BASupportExpressSrvcUpdater" OR ServiceName contains "BASupportExpressStandaloneService" OR ServiceName contains "chromoting" OR ServiceName contains "GoToAssist" OR ServiceName contains "GoToMyPC" OR ServiceName contains "jumpcloud" OR ServiceName contains "LMIGuardianSvc" OR ServiceName contains "LogMeIn" OR ServiceName contains "monblanking" OR ServiceName contains "Parsec" OR ServiceName contains "RManService" OR ServiceName contains "RPCPerformanceService" OR ServiceName contains "RPCService" OR ServiceName contains "SplashtopRemoteService" OR ServiceName contains "SSUService" OR ServiceName contains "TeamViewer" OR ServiceName contains "TightVNC" OR ServiceName contains "vncserver" OR ServiceName contains "Zoho"))
