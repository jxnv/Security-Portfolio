// Title: Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging
// ID: ae2bdd58-0681-48ac-be7f-58ab4e593458
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-05
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects attempts to remove Windows Defender configuration using the 'MpPreference' cmdlet
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText: "*Remove-MpPreference*") AND ((ScriptBlockText: "*-ControlledFolderAccessProtectedFolders *" OR ScriptBlockText: "*-AttackSurfaceReductionRules_Ids *" OR ScriptBlockText: "*-AttackSurfaceReductionRules_Actions *" OR ScriptBlockText: "*-CheckForSignaturesBeforeRunningScan *")))
