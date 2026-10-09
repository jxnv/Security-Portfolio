-- Title: DNS Query To Ufile.io
-- ID: 1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b
-- Status: test
-- Level: low
-- Author: yatinwad, TheDFIRReport
-- Date: 2022-06-23
-- Tags: attack.exfiltration, attack.t1567.002
-- Description: Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (QueryName ILIKE '%ufile.io%')
