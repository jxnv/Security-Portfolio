-- Title: Potential Attachment Manager Settings Associations Tamper
-- ID: a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-01
-- Tags: attack.defense-impairment
-- Description: Detects tampering with attachment manager settings policies associations to lower the default file type risks (See reference for more information)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\%') AND ((TargetObject ILIKE '%\\DefaultFileTypeRisk' AND Details = 'DWORD (0x00006152)') OR (TargetObject ILIKE '%\\LowRiskFileTypes' AND (Details ILIKE '%.zip;%' OR Details ILIKE '%.rar;%' OR Details ILIKE '%.exe;%' OR Details ILIKE '%.bat;%' OR Details ILIKE '%.com;%' OR Details ILIKE '%.cmd;%' OR Details ILIKE '%.reg;%' OR Details ILIKE '%.msi;%' OR Details ILIKE '%.htm;%' OR Details ILIKE '%.html;%'))))
