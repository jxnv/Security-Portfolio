-- Title: HackTool - SysmonEnte Execution
-- ID: d29ada0f-af45-4f27-8f32-f7b77c3dbc4e
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-09-07
-- Tags: attack.defense-impairment, attack.t1685.001
-- Description: Detects the use of SysmonEnte, a tool to attack the integrity of Sysmon
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((TargetImage ILIKE '%:\\Windows\\Sysmon.exe%' OR TargetImage ILIKE '%:\\Windows\\Sysmon64.exe%' OR TargetImage ILIKE '%:\\Windows\\Sysmon64a.exe%') AND GrantedAccess = '0x1400') AND NOT ((((SourceImage ILIKE '%:\\Program Files (x86)\\%' OR SourceImage ILIKE '%:\\Program Files\\%' OR SourceImage ILIKE '%:\\Windows\\System32\\%' OR SourceImage ILIKE '%:\\Windows\\SysWOW64\\%')) OR (SourceImage ILIKE '%:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\%' AND SourceImage ILIKE '%\\MsMpEng.exe')))) OR (CallTrace = 'Ente'))
