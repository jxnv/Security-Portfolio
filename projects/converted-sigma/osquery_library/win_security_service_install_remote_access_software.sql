-- Title: Remote Access Tool Services Have Been Installed - Security
-- ID: c8b00925-926c-47e3-beea-298fd563728e
-- Status: test
-- Level: medium
-- Author: Connor Martin, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-23
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1543.003, attack.t1569.002
-- Description: Detects service installation of different remote access tools software. These software are often abused by threat actors to perform
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (EventID = '4697' AND (ServiceName LIKE '%AmmyyAdmin%' OR ServiceName LIKE '%AnyDesk%' OR ServiceName LIKE '%Atera%' OR ServiceName LIKE '%BASupportExpressSrvcUpdater%' OR ServiceName LIKE '%BASupportExpressStandaloneService%' OR ServiceName LIKE '%chromoting%' OR ServiceName LIKE '%GoToAssist%' OR ServiceName LIKE '%GoToMyPC%' OR ServiceName LIKE '%jumpcloud%' OR ServiceName LIKE '%LMIGuardianSvc%' OR ServiceName LIKE '%LogMeIn%' OR ServiceName LIKE '%monblanking%' OR ServiceName LIKE '%Parsec%' OR ServiceName LIKE '%RManService%' OR ServiceName LIKE '%RPCPerformanceService%' OR ServiceName LIKE '%RPCService%' OR ServiceName LIKE '%SplashtopRemoteService%' OR ServiceName LIKE '%SSUService%' OR ServiceName LIKE '%TeamViewer%' OR ServiceName LIKE '%TightVNC%' OR ServiceName LIKE '%vncserver%' OR ServiceName LIKE '%Zoho%'))
