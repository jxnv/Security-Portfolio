-- Title: Alternate PowerShell Hosts - PowerShell Module
-- ID: 64e8e417-c19a-475a-8d19-98ea705394cc
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez @Cyb3rWard0g
-- Date: 2019-08-11
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ContextInfo ILIKE '%*%') AND NOT (((ContextInfo ILIKE '%C:\\Windows\\system32\\dsac.exe%') OR (ContextInfo ILIKE '%ConfigSyncRun.exe%') OR ((Payload ILIKE '%Update-Help%' OR Payload ILIKE '%Failed to update Help for the module%')) OR ((ContextInfo ILIKE '%= powershell%' OR ContextInfo ILIKE '%= C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell%' OR ContextInfo ILIKE '%= C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell%' OR ContextInfo ILIKE '%= C:/Windows/System32/WindowsPowerShell/v1.0/powershell%' OR ContextInfo ILIKE '%= C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell%' OR ContextInfo ILIKE '%= \\\\\\?\\?\\C:Windows\\System32\\WindowsPowerShell\\v1.0\\powershell%' OR ContextInfo ILIKE '%= \\\\\\?\\?\\C:Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell%')) OR (ContextInfo ILIKE '%= C:\\WINDOWS\\System32\\sdiagnhost.exe -Embedding%') OR (ContextInfo ILIKE '%C:\\Windows\\system32\\wsmprovhost.exe -Embedding%'))))
