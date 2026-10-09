// Title: PowerShell Logging Disabled Via Registry Key Tampering
// ID: fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7
// Status: test
// Level: high
// Author: frack113
// Date: 2022-04-02
// Tags: attack.stealth, attack.defense-impairment, attack.t1564.001, attack.t1112, attack.persistence
// Description: Detects changes to the registry for the currently logged-in user. In order to disable PowerShell module logging, script block logging or transcription and script execution logging
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Microsoft\\Windows\\PowerShell\\" or TargetObject contains "\\Microsoft\\PowerShellCore\\") and (TargetObject endswith "\\ModuleLogging\\EnableModuleLogging" or TargetObject endswith "\\ScriptBlockLogging\\EnableScriptBlockLogging" or TargetObject endswith "\\ScriptBlockLogging\\EnableScriptBlockInvocationLogging" or TargetObject endswith "\\Transcription\\EnableTranscripting" or TargetObject endswith "\\Transcription\\EnableInvocationHeader" or TargetObject endswith "\\EnableScripts") and Details = "DWORD (0x00000000)")
