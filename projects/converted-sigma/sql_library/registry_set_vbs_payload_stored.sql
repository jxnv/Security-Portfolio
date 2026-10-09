-- Title: VBScript Payload Stored in Registry
-- ID: 46490193-1b22-4c29-bdd6-5bf63907216f
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-03-05
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects VBScript content stored into registry keys as seen being used by UNC2452 group
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%Software\\Microsoft\\Windows\\CurrentVersion%' AND (Details ILIKE '%vbscript:%' OR Details ILIKE '%jscript:%' OR Details ILIKE '%mshtml,%' OR Details ILIKE '%RunHTMLApplication%' OR Details ILIKE '%Execute(%' OR Details ILIKE '%CreateObject%' OR Details ILIKE '%window.close%')) AND NOT (((TargetObject ILIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Run%') OR (Image ILIKE '%\\msiexec.exe' AND TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\%' AND (Details ILIKE '%\\Microsoft.NET\\Primary Interop Assemblies\\Microsoft.mshtml.dll%' OR Details ILIKE '%<\\Microsoft.mshtml,fileVersion=%' OR Details ILIKE '%_mshtml_dll_%' OR Details ILIKE '%<\\Microsoft.mshtml,culture=%')))))
