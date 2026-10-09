-- Title: Hidden User Creation
-- ID: b22a5b36-2431-493a-8be1-0bae56c28ef3
-- Status: test
-- Level: medium
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-10
-- Tags: attack.stealth, attack.t1564.002
-- Description: Detects creation of a hidden user account on macOS (UserID < 500) or with IsHidden option
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%/dscl' AND CommandLine ILIKE '%create%') AND (CommandLine ILIKE '%UniqueID%' AND REGEXP_LIKE(CommandLine, '([0-9]|[1-9][0-9]|[1-4][0-9]{2})'))) OR ((Image ILIKE '%/dscl' AND CommandLine ILIKE '%create%') AND ((CommandLine ILIKE '%IsHidden%') AND ((CommandLine ILIKE '%true%' OR CommandLine ILIKE '%yes%' OR CommandLine ILIKE '%1%')))))
