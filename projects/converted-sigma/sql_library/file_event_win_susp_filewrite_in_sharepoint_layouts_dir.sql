-- Title: Suspicious File Write to SharePoint Layouts Directory
-- ID: 1f0489be-b496-4ddf-b3a9-5900f2044e9c
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-07-24
-- Tags: attack.initial-access, attack.t1190, attack.persistence, attack.t1505.003
-- Description: Detects suspicious file writes to SharePoint layouts directory which could indicate webshell activity or post-exploitation.
-- This behavior has been observed in the exploitation of SharePoint vulnerabilities such as CVE-2025-49704, CVE-2025-49706 or CVE-2025-53770.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\w3wp.exe') AND (TargetFilename ILIKE 'C:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\%' OR TargetFilename ILIKE 'C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\Web Server Extensions\\%') AND (TargetFilename ILIKE '%\\15\\TEMPLATE\\LAYOUTS\\%' OR TargetFilename ILIKE '%\\16\\TEMPLATE\\LAYOUTS\\%') AND (TargetFilename ILIKE '%.asax' OR TargetFilename ILIKE '%.ascx' OR TargetFilename ILIKE '%.ashx' OR TargetFilename ILIKE '%.asmx' OR TargetFilename ILIKE '%.asp' OR TargetFilename ILIKE '%.aspx' OR TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.cmd' OR TargetFilename ILIKE '%.cer' OR TargetFilename ILIKE '%.config' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.js' OR TargetFilename ILIKE '%.jsp' OR TargetFilename ILIKE '%.jspx' OR TargetFilename ILIKE '%.php' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.vbs'))
