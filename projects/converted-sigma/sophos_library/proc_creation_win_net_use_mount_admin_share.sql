-- Title: Windows Admin Share Mount Via Net.EXE
-- ID: 3abd6094-7027-475f-9630-8ab9be7b9725
-- Status: test
-- Level: medium
-- Author: oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, wagga
-- Date: 2020-10-05
-- Tags: attack.lateral-movement, attack.t1021.002
-- Description: Detects when an admin share is mounted using net.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% use %' AND CommandLine ILIKE '% \\\\\\\\*\\\\*$%')) AND (((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe')) OR ((OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe'))))
