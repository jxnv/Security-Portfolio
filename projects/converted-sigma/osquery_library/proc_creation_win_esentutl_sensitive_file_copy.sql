-- Title: Copying Sensitive Files with Credential Data
-- ID: e7be6119-fc37-43f0-ad4f-1f3f99be2f9f
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
-- Date: 2019-10-22
-- Tags: attack.credential-access, attack.t1003.002, attack.t1003.003, car.2013-07-001, attack.s0404
-- Description: Files with well-known filenames (sensitive files with credential data) copying
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%vss%' OR CommandLine LIKE '% /m %' OR CommandLine LIKE '% /y %')) AND ((Image="*\\esentutl.exe") OR (OriginalFileName = '\\esentutl.exe'))) OR ((CommandLine LIKE '%\\config\\RegBack\\sam%' OR CommandLine LIKE '%\\config\\RegBack\\security%' OR CommandLine LIKE '%\\config\\RegBack\\system%' OR CommandLine LIKE '%\\config\\sam%' OR CommandLine LIKE '%\\config\\security%' OR CommandLine LIKE '%\\config\\system %' OR CommandLine LIKE '%\\repair\\sam%' OR CommandLine LIKE '%\\repair\\security%' OR CommandLine LIKE '%\\repair\\system%' OR CommandLine LIKE '%\\windows\\ntds\\ntds.dit%')))
