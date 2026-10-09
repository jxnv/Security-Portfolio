-- Title: Successful IIS Shortname Fuzzing Scan
-- ID: 7cb02516-6d95-4ffc-8eee-162075e111ac
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-10-06
-- Tags: attack.initial-access, attack.t1190
-- Description: When IIS uses an old .Net Framework it's possible to enumerate folders with the symbol "~"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (cs-uri-query ILIKE '%~1%' AND cs-uri-query ILIKE '%a.aspx' AND (cs-method = 'GET' OR cs-method = 'OPTIONS') AND (sc-status = 200 OR sc-status = 301))
