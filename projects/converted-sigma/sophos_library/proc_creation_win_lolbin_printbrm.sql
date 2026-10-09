-- Title: PrintBrm ZIP Creation of Extraction
-- ID: cafeeba3-01da-4ab4-b6c4-a31b1d9730c7
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-05-02
-- Tags: attack.command-and-control, attack.stealth, attack.t1105, attack.t1564.004
-- Description: Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\PrintBrm.exe' AND (CommandLine ILIKE '% -f%' AND CommandLine ILIKE '%.zip%'))
