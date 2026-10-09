-- Title: Potential Persistence Via DLLPathOverride
-- ID: a1b1fd53-9c4a-444c-bae0-34a330fc7aa8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-21
-- Tags: attack.persistence
-- Description: Detects when an attacker adds a new "DLLPathOverride" value to the "Natural Language" key in order to achieve persistence which will get invoked by "SearchIndexer.exe" process
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\SYSTEM\\CurrentControlSet\\Control\\ContentIndex\\Language\\%') AND ((TargetObject LIKE '%\\StemmerDLLPathOverride%' OR TargetObject LIKE '%\\WBDLLPathOverride%' OR TargetObject LIKE '%\\StemmerClass%' OR TargetObject LIKE '%\\WBreakerClass%')))
