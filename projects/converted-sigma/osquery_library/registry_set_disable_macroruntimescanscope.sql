-- Title: Disable Macro Runtime Scan Scope
-- ID: ab871450-37dc-4a3a-997f-6662aa8ae0f1
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-25
-- Tags: attack.defense-impairment
-- Description: Detects tampering with the MacroRuntimeScanScope registry key to disable runtime scanning of enabled macros
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\SOFTWARE\\%' AND TargetObject LIKE '%\\Microsoft\\Office\\%' AND TargetObject LIKE '%\\Common\\Security%') AND TargetObject="*\\MacroRuntimeScanScope" AND Details = 'DWORD (0x00000000)')
