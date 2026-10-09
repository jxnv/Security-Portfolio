-- Title: Wab/Wabmig Unusual Parent Or Child Processes
-- ID: 63d1ccc0-2a43-4f4b-9289-361b308991ff
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-12
-- Tags: attack.execution, attack.stealth
-- Description: Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ParentImage ILIKE '%\\wab.exe' OR ParentImage ILIKE '%\\wabmig.exe')) OR ((ParentImage ILIKE '%\\WmiPrvSE.exe' OR ParentImage ILIKE '%\\svchost.exe' OR ParentImage ILIKE '%\\dllhost.exe') AND (Image ILIKE '%\\wab.exe' OR Image ILIKE '%\\wabmig.exe')))
