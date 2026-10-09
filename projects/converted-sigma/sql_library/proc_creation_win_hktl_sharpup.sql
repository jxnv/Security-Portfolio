-- Title: HackTool - SharpUp PrivEsc Tool Execution
-- ID: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-20
-- Tags: attack.persistence, attack.privilege-escalation, attack.discovery, attack.execution, attack.stealth, attack.t1615, attack.t1569.002, attack.t1574.005
-- Description: Detects the use of SharpUp, a tool for local privilege escalation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\SharpUp.exe') OR (Description = 'SharpUp') OR ((CommandLine ILIKE '%HijackablePaths%' OR CommandLine ILIKE '%UnquotedServicePath%' OR CommandLine ILIKE '%ProcessDLLHijack%' OR CommandLine ILIKE '%ModifiableServiceBinaries%' OR CommandLine ILIKE '%ModifiableScheduledTask%' OR CommandLine ILIKE '%DomainGPPPassword%' OR CommandLine ILIKE '%CachedGPPPassword%')))
