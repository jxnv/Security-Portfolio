-- Title: Potential Initial Access via DLL Search Order Hijacking
-- ID: dbbd9f66-2ed3-4ca2-98a4-6ea985dd1a1c
-- Status: test
-- Level: medium
-- Author: Tim Rauch (rule), Elastic (idea)
-- Date: 2022-10-21
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1566, attack.t1566.001, attack.initial-access, attack.t1574, attack.t1574.001
-- Description: Detects attempts to create a DLL file to a known desktop application dependencies folder such as Slack, Teams or OneDrive and by an unusual process. This may indicate an attempt to load a malicious module via DLL search order hijacking.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\winword.exe' OR Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\MSACCESS.EXE' OR Image ILIKE '%\\MSPUB.EXE' OR Image ILIKE '%\\fltldr.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\curl.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND TargetFilename ILIKE '%.dll' AND (TargetFilename ILIKE '%\\Users\\%' AND TargetFilename ILIKE '%\\AppData\\%') AND (TargetFilename ILIKE '%\\Microsoft\\OneDrive\\%' OR TargetFilename ILIKE '%\\Microsoft OneDrive\\%' OR TargetFilename ILIKE '%\\Microsoft\\Teams\\%' OR TargetFilename ILIKE '%\\Local\\slack\\app-%' OR TargetFilename ILIKE '%\\Local\\Programs\\Microsoft VS Code\\%')) AND NOT ((Image ILIKE '%\\cmd.exe' AND (TargetFilename ILIKE '%\\Users\\%' AND TargetFilename ILIKE '%\\AppData\\%' AND TargetFilename ILIKE '%\\Microsoft\\OneDrive\\%' AND TargetFilename ILIKE '%\\api-ms-win-core-%'))))
