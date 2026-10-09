-- Title: HackTool Service Registration or Execution
-- ID: d26ce60c-2151-403c-9a42-49420d87b5e4
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-21
-- Tags: attack.execution, attack.t1569.002, attack.s0029
-- Description: Detects installation or execution of services
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Provider_Name = 'Service Control Manager' AND (EventID = 7045 OR EventID = 7036)) AND ((ImagePath ILIKE '%bypass%') OR ((ServiceName ILIKE '%cachedump%' OR ServiceName ILIKE '%DumpSvc%' OR ServiceName ILIKE '%gsecdump%' OR ServiceName ILIKE '%pwdump%' OR ServiceName ILIKE '%UACBypassedService%' OR ServiceName ILIKE '%WCE SERVICE%' OR ServiceName ILIKE '%WCESERVICE%' OR ServiceName ILIKE '%winexesvc%'))))
