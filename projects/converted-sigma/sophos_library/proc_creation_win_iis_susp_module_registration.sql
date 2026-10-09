-- Title: Suspicious IIS Module Registration
-- ID: 043c4b8b-3a54-4780-9682-081cb6b8185c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Microsoft (idea)
-- Date: 2022-08-04
-- Tags: attack.persistence, attack.t1505.004
-- Description: Detects a suspicious IIS module registration as described in Microsoft threat report on IIS backdoors
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\w3wp.exe') AND ((CommandLine ILIKE '%appcmd.exe add module%') OR (CommandLine ILIKE '% system.enterpriseservices.internal.publish%' AND Image ILIKE '%\\powershell.exe') OR ((CommandLine ILIKE '%gacutil%' AND CommandLine ILIKE '% /I%'))))
