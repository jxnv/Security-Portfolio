-- Title: Potential Manage-bde.wsf Abuse To Proxy Execution
-- ID: c363385c-f75d-4753-a108-c1a8e28bdbda
-- Status: test
-- Level: high
-- Author: oscd.community, Natalia Shornikova, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2020-10-13
-- Tags: attack.stealth, attack.t1216
-- Description: Detects potential abuse of the "manage-bde.wsf" script as a LOLBIN to proxy execution
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%manage-bde.wsf%') AND ((Image ILIKE '%\\wscript.exe') OR (OriginalFileName = 'wscript.exe'))) OR (((ParentImage ILIKE '%\\cscript.exe' OR ParentImage ILIKE '%\\wscript.exe') AND ParentCommandLine ILIKE '%manage-bde.wsf%') AND NOT ((Image ILIKE '%\\cmd.exe'))))
