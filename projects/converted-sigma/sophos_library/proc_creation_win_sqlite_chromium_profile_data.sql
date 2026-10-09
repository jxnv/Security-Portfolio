-- Title: SQLite Chromium Profile Data DB Access
-- ID: 24c77512-782b-448a-8950-eddb0785fc71
-- Status: test
-- Level: high
-- Author: TropChaud
-- Date: 2022-12-19
-- Tags: attack.credential-access, attack.t1539, attack.t1555.003, attack.collection, attack.t1005
-- Description: Detect usage of the "sqlite" binary to query databases in Chromium-based browsers for potential data stealing.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%\\User Data\\%' OR CommandLine ILIKE '%\\Opera Software\\%' OR CommandLine ILIKE '%\\ChromiumViewer\\%')) AND ((CommandLine ILIKE '%Login Data%' OR CommandLine ILIKE '%Cookies%' OR CommandLine ILIKE '%Web Data%' OR CommandLine ILIKE '%History%' OR CommandLine ILIKE '%Bookmarks%')) AND ((Product = 'SQLite') OR ((Image ILIKE '%\\sqlite.exe' OR Image ILIKE '%\\sqlite3.exe'))))
