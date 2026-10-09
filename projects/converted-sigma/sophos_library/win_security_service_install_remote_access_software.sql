-- Title: Remote Access Tool Services Have Been Installed - Security
-- ID: c8b00925-926c-47e3-beea-298fd563728e
-- Status: test
-- Level: medium
-- Author: Connor Martin, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-23
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1543.003, attack.t1569.002
-- Description: Detects service installation of different remote access tools software. These software are often abused by threat actors to perform
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 4697 AND (ServiceName ILIKE '%AmmyyAdmin%' OR ServiceName ILIKE '%AnyDesk%' OR ServiceName ILIKE '%Atera%' OR ServiceName ILIKE '%BASupportExpressSrvcUpdater%' OR ServiceName ILIKE '%BASupportExpressStandaloneService%' OR ServiceName ILIKE '%chromoting%' OR ServiceName ILIKE '%GoToAssist%' OR ServiceName ILIKE '%GoToMyPC%' OR ServiceName ILIKE '%jumpcloud%' OR ServiceName ILIKE '%LMIGuardianSvc%' OR ServiceName ILIKE '%LogMeIn%' OR ServiceName ILIKE '%monblanking%' OR ServiceName ILIKE '%Parsec%' OR ServiceName ILIKE '%RManService%' OR ServiceName ILIKE '%RPCPerformanceService%' OR ServiceName ILIKE '%RPCService%' OR ServiceName ILIKE '%SplashtopRemoteService%' OR ServiceName ILIKE '%SSUService%' OR ServiceName ILIKE '%TeamViewer%' OR ServiceName ILIKE '%TightVNC%' OR ServiceName ILIKE '%vncserver%' OR ServiceName ILIKE '%Zoho%'))
