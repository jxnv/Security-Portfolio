-- Title: Suspicious SQL Error Messages
-- ID: 8a670c6d-7189-4b1c-8017-a417ca84a086
-- Status: test
-- Level: high
-- Author: Bjoern Kimminich
-- Date: 2017-11-27
-- Tags: attack.initial-access, attack.t1190
-- Description: Detects SQL error messages that indicate probing for an injection attack
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ("quoted string not properly terminated" OR "You have an error in your SQL syntax" OR "Unclosed quotation mark" OR "near \"*\": syntax error" OR "SELECTs to the left and right of UNION do not have the same number of result columns")
