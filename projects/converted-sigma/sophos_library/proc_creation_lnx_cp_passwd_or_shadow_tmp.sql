-- Title: Copy Passwd Or Shadow From TMP Path
-- ID: fa4aaed5-4fe0-498d-bbc0-08e3346387ba
-- Status: test
-- Level: high
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2023-01-31
-- Tags: attack.credential-access, attack.t1552.001
-- Description: Detects when the file "passwd" or "shadow" is copied from tmp path
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%passwd%' OR CommandLine ILIKE '%shadow%')) AND (Image ILIKE '%/cp') AND (CommandLine ILIKE '%/tmp/%'))
