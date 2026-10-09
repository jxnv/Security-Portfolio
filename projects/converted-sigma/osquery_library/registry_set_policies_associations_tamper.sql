-- Title: Potential Attachment Manager Settings Associations Tamper
-- ID: a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-01
-- Tags: attack.defense-impairment
-- Description: Detects tampering with attachment manager settings policies associations to lower the default file type risks (See reference for more information)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\%') AND ((TargetObject="*\\DefaultFileTypeRisk" AND Details = 'DWORD (0x00006152)') OR (TargetObject="*\\LowRiskFileTypes" AND (Details LIKE '%.zip;%' OR Details LIKE '%.rar;%' OR Details LIKE '%.exe;%' OR Details LIKE '%.bat;%' OR Details LIKE '%.com;%' OR Details LIKE '%.cmd;%' OR Details LIKE '%.reg;%' OR Details LIKE '%.msi;%' OR Details LIKE '%.htm;%' OR Details LIKE '%.html;%'))))
