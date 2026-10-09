-- Title: VBScript Payload Stored in Registry
-- ID: 46490193-1b22-4c29-bdd6-5bf63907216f
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-03-05
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects VBScript content stored into registry keys as seen being used by UNC2452 group
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%Software\\Microsoft\\Windows\\CurrentVersion%' AND (Details LIKE '%vbscript:%' OR Details LIKE '%jscript:%' OR Details LIKE '%mshtml,%' OR Details LIKE '%RunHTMLApplication%' OR Details LIKE '%Execute(%' OR Details LIKE '%CreateObject%' OR Details LIKE '%window.close%')) AND NOT (((TargetObject LIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Run%') OR (Image="*\\msiexec.exe" AND TargetObject LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\%' AND (Details LIKE '%\\Microsoft.NET\\Primary Interop Assemblies\\Microsoft.mshtml.dll%' OR Details LIKE '%<\\Microsoft.mshtml,fileVersion=%' OR Details LIKE '%_mshtml_dll_%' OR Details LIKE '%<\\Microsoft.mshtml,culture=%')))))
