-- Title: SQLite Chromium Profile Data DB Access
-- ID: 24c77512-782b-448a-8950-eddb0785fc71
-- Status: test
-- Level: high
-- Author: TropChaud
-- Date: 2022-12-19
-- Tags: attack.credential-access, attack.t1539, attack.t1555.003, attack.collection, attack.t1005
-- Description: Detect usage of the "sqlite" binary to query databases in Chromium-based browsers for potential data stealing.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%\\User Data\\%' OR CommandLine LIKE '%\\Opera Software\\%' OR CommandLine LIKE '%\\ChromiumViewer\\%')) AND ((CommandLine LIKE '%Login Data%' OR CommandLine LIKE '%Cookies%' OR CommandLine LIKE '%Web Data%' OR CommandLine LIKE '%History%' OR CommandLine LIKE '%Bookmarks%')) AND ((Product = 'SQLite') OR ((Image="*\\sqlite.exe" OR Image="*\\sqlite3.exe"))))
