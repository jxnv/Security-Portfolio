-- Title: PowerShell Logging Disabled Via Registry Key Tampering
-- ID: fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-04-02
-- Tags: attack.stealth, attack.defense-impairment, attack.t1564.001, attack.t1112, attack.persistence
-- Description: Detects changes to the registry for the currently logged-in user. In order to disable PowerShell module logging, script block logging or transcription and script execution logging
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\Microsoft\\Windows\\PowerShell\\%' OR TargetObject ILIKE '%\\Microsoft\\PowerShellCore\\%') AND (TargetObject ILIKE '%\\ModuleLogging\\EnableModuleLogging' OR TargetObject ILIKE '%\\ScriptBlockLogging\\EnableScriptBlockLogging' OR TargetObject ILIKE '%\\ScriptBlockLogging\\EnableScriptBlockInvocationLogging' OR TargetObject ILIKE '%\\Transcription\\EnableTranscripting' OR TargetObject ILIKE '%\\Transcription\\EnableInvocationHeader' OR TargetObject ILIKE '%\\EnableScripts') AND Details = 'DWORD (0x00000000)')
