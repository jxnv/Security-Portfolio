-- Title: Enumerate All Information With Whoami.EXE
-- ID: c248c896-e412-4279-8c15-1c558067b6fa
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-12-04
-- Tags: attack.discovery, attack.t1033, car.2016-03-001
-- Description: Detects the execution of "whoami.exe" with the "/all" flag
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '% -all%') AND ((Image ILIKE '%\\whoami.exe') OR (OriginalFileName = 'whoami.exe')))
