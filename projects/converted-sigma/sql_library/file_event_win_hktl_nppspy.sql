-- Title: HackTool - NPPSpy Hacktool Usage
-- ID: cad1fe90-2406-44dc-bd03-59d0b58fe722
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-11-29
-- Tags: attack.credential-access
-- Description: Detects the use of NPPSpy hacktool that stores cleartext passwords of users that logged in to a local file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetFilename ILIKE '%\\NPPSpy.txt' OR TargetFilename ILIKE '%\\NPPSpy.dll'))
