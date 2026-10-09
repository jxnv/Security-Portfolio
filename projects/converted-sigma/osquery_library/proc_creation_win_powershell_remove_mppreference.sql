-- Title: Tamper Windows Defender Remove-MpPreference
-- ID: 07e3cb2c-0608-410d-be4b-1511cb1a0448
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-05
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%Remove-MpPreference%') AND ((CommandLine LIKE '%-ControlledFolderAccessProtectedFolders %' OR CommandLine LIKE '%-AttackSurfaceReductionRules_Ids %' OR CommandLine LIKE '%-AttackSurfaceReductionRules_Actions %' OR CommandLine LIKE '%-CheckForSignaturesBeforeRunningScan %')))
