-- Title: PUA - Potential PE Metadata Tamper Using Rcedit
-- ID: 0c92f2e6-f08f-4b73-9216-ecb0ca634689
-- Status: test
-- Level: medium
-- Author: Micah Babinski
-- Date: 2022-12-11
-- Tags: attack.stealth, attack.t1036.003, attack.t1036, attack.t1027.005, attack.t1027
-- Description: Detects the use of rcedit to potentially alter executable PE metadata properties, which could conceal efforts to rename system utilities for defense evasion.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%OriginalFileName%' OR CommandLine ILIKE '%CompanyName%' OR CommandLine ILIKE '%FileDescription%' OR CommandLine ILIKE '%ProductName%' OR CommandLine ILIKE '%ProductVersion%' OR CommandLine ILIKE '%LegalCopyright%')) AND (CommandLine ILIKE '%--set-%') AND (((Image ILIKE '%\\rcedit-x64.exe' OR Image ILIKE '%\\rcedit-x86.exe')) OR (Description = 'Edit resources of exe') OR (Product = 'rcedit')))
