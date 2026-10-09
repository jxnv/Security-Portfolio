-- Title: Potential Persistence Via DLLPathOverride
-- ID: a1b1fd53-9c4a-444c-bae0-34a330fc7aa8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-21
-- Tags: attack.persistence
-- Description: Detects when an attacker adds a new "DLLPathOverride" value to the "Natural Language" key in order to achieve persistence which will get invoked by "SearchIndexer.exe" process
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\SYSTEM\\CurrentControlSet\\Control\\ContentIndex\\Language\\%') AND ((TargetObject ILIKE '%\\StemmerDLLPathOverride%' OR TargetObject ILIKE '%\\WBDLLPathOverride%' OR TargetObject ILIKE '%\\StemmerClass%' OR TargetObject ILIKE '%\\WBreakerClass%')))
