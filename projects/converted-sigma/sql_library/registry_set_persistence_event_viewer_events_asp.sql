-- Title: Potential Persistence Via Event Viewer Events.asp
-- ID: a1e11042-a74a-46e6-b07c-c4ce8ecc239b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-17
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects potential registry persistence technique using the Event Viewer "Events.asp" technique
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgram%' OR TargetObject ILIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionURL%')) AND NOT (((Details = '(Empty)') OR (Image ILIKE '%C:\\WINDOWS\\system32\\svchost.exe' AND TargetObject ILIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgram' AND Details = '%%SystemRoot%%\\PCHealth\\HelpCtr\\Binaries\\HelpCtr.exe') OR (Image ILIKE '%C:\\WINDOWS\\system32\\svchost.exe' AND TargetObject ILIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgramCommandLineParameters' AND Details = '-url hcp://services/centers/support?topic=%%s') OR (Details = 'http://go.microsoft.com/fwlink/events.asp'))))
