-- Title: Findstr GPP Passwords
-- ID: 91a2c315-9ee6-4052-a853-6f6a8238f90d
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-12-27
-- Tags: attack.credential-access, attack.t1552.006
-- Description: Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller. This value can be decrypted with gpp-decrypt.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%cpassword%' AND CommandLine ILIKE '%\\sysvol\\%' AND CommandLine ILIKE '%.xml%')) AND (((Image ILIKE '%\\find.exe' OR Image ILIKE '%\\findstr.exe')) OR ((OriginalFileName = 'FIND.EXE' OR OriginalFileName = 'FINDSTR.EXE'))))
