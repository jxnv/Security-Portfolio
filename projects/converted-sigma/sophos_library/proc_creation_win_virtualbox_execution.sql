-- Title: Virtualbox Driver Installation or Starting of VMs
-- ID: bab049ca-7471-4828-9024-38279a4c04da
-- Status: test
-- Level: low
-- Author: Janantha Marasinghe
-- Date: 2020-09-26
-- Tags: attack.stealth, attack.t1564.006, attack.t1564
-- Description: Adversaries can carry out malicious operations using a virtual instance to avoid detection. This rule is built to detect the registration of the Virtualbox driver or start of a Virtualbox VM.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%VBoxRT.dll,RTR3Init%' OR CommandLine ILIKE '%VBoxC.dll%' OR CommandLine ILIKE '%VBoxDrv.sys%')) OR ((CommandLine ILIKE '%startvm%' OR CommandLine ILIKE '%controlvm%')))
