-- Title: Office Application Initiated Network Connection Over Uncommon Ports
-- ID: 3b5ba899-9842-4bc2-acc2-12308498bf42
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-12
-- Tags: attack.command-and-control, attack.stealth
-- Description: Detects an office suit application (Word, Excel, PowerPoint, Outlook) communicating to target systems over uncommon ports.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Initiated = 'true' AND (Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\outlook.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\winword.exe' OR Image ILIKE '%\\wordview.exe')) AND NOT ((((DestinationPort = 53 OR DestinationPort = 80 OR DestinationPort = 139 OR DestinationPort = 389 OR DestinationPort = 443 OR DestinationPort = 445 OR DestinationPort = 3268)) OR (Image ILIKE '%:\\Program Files\\Microsoft Office\\%' AND Image ILIKE '%\\OUTLOOK.EXE' AND (DestinationPort = 143 OR DestinationPort = 465 OR DestinationPort = 587 OR DestinationPort = 993 OR DestinationPort = 995)))))
