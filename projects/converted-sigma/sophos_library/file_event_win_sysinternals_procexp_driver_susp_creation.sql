-- Title: Process Explorer Driver Creation By Non-Sysinternals Binary
-- ID: de46c52b-0bf8-4936-a327-aace94f94ac6
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2023-05-05
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1068
-- Description: Detects creation of the Process Explorer drivers by processes other than Process Explorer (procexp) itself.
-- Hack tools or malware may use the Process Explorer driver to elevate privileges, drops it to disk for a few moments, runs a service using that driver and removes it afterwards.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%\\PROCEXP%' AND TargetFilename ILIKE '%.sys') AND NOT (((Image ILIKE '%\\procexp.exe' OR Image ILIKE '%\\procexp64.exe' OR Image ILIKE '%\\procexp64a.exe'))))
