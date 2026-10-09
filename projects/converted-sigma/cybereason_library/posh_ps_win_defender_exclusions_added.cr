// Title: Windows Defender Exclusions Added - PowerShell
// ID: c1344fa2-323b-4d2e-9176-84b4d4821c88
// Status: test
// Level: medium
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-16
// Tags: attack.defense-impairment, attack.t1685, attack.execution, attack.t1059
// Description: Detects modifications to the Windows Defender configuration settings using PowerShell to add exclusions
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText contains " -ExclusionPath " OR ScriptBlockText contains " -ExclusionExtension " OR ScriptBlockText contains " -ExclusionProcess " OR ScriptBlockText contains " -ExclusionIpAddress ")) AND ((ScriptBlockText contains "Add-MpPreference " OR ScriptBlockText contains "Set-MpPreference ")))
