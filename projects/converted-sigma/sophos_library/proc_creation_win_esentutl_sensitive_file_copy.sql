-- Title: Copying Sensitive Files with Credential Data
-- ID: e7be6119-fc37-43f0-ad4f-1f3f99be2f9f
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
-- Date: 2019-10-22
-- Tags: attack.credential-access, attack.t1003.002, attack.t1003.003, car.2013-07-001, attack.s0404
-- Description: Files with well-known filenames (sensitive files with credential data) copying
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%vss%' OR CommandLine ILIKE '% /m %' OR CommandLine ILIKE '% /y %')) AND ((Image ILIKE '%\\esentutl.exe') OR (OriginalFileName = '\\esentutl.exe'))) OR ((CommandLine ILIKE '%\\config\\RegBack\\sam%' OR CommandLine ILIKE '%\\config\\RegBack\\security%' OR CommandLine ILIKE '%\\config\\RegBack\\system%' OR CommandLine ILIKE '%\\config\\sam%' OR CommandLine ILIKE '%\\config\\security%' OR CommandLine ILIKE '%\\config\\system %' OR CommandLine ILIKE '%\\repair\\sam%' OR CommandLine ILIKE '%\\repair\\security%' OR CommandLine ILIKE '%\\repair\\system%' OR CommandLine ILIKE '%\\windows\\ntds\\ntds.dit%')))
