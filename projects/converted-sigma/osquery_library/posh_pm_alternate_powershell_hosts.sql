-- Title: Alternate PowerShell Hosts - PowerShell Module
-- ID: 64e8e417-c19a-475a-8d19-98ea705394cc
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez @Cyb3rWard0g
-- Date: 2019-08-11
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ContextInfo LIKE '%*%') AND NOT (((ContextInfo LIKE '%C:\\Windows\\system32\\dsac.exe%') OR (ContextInfo LIKE '%ConfigSyncRun.exe%') OR ((Payload LIKE '%Update-Help%' OR Payload LIKE '%Failed to update Help for the module%')) OR ((ContextInfo LIKE '%= powershell%' OR ContextInfo LIKE '%= C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell%' OR ContextInfo LIKE '%= C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell%' OR ContextInfo LIKE '%= C:/Windows/System32/WindowsPowerShell/v1.0/powershell%' OR ContextInfo LIKE '%= C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell%' OR ContextInfo LIKE '%= \\\\\\?\\?\\C:Windows\\System32\\WindowsPowerShell\\v1.0\\powershell%' OR ContextInfo LIKE '%= \\\\\\?\\?\\C:Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell%')) OR (ContextInfo LIKE '%= C:\\WINDOWS\\System32\\sdiagnhost.exe -Embedding%') OR (ContextInfo LIKE '%C:\\Windows\\system32\\wsmprovhost.exe -Embedding%'))))
