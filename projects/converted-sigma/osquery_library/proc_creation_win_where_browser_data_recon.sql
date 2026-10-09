-- Title: Suspicious Where Execution
-- ID: 725a9768-0f5e-4cb3-aec2-bc5719c6831a
-- Status: test
-- Level: low
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-13
-- Tags: attack.discovery, attack.t1217
-- Description: Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
-- Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
-- internal network resources such as servers, tools/dashboards, or other related infrastructure.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\where.exe") OR (OriginalFileName = 'where.exe')) AND ((CommandLine LIKE '%places.sqlite%' OR CommandLine LIKE '%cookies.sqlite%' OR CommandLine LIKE '%formhistory.sqlite%' OR CommandLine LIKE '%logins.json%' OR CommandLine LIKE '%key4.db%' OR CommandLine LIKE '%key3.db%' OR CommandLine LIKE '%sessionstore.jsonlz4%' OR CommandLine LIKE '%History%' OR CommandLine LIKE '%Bookmarks%' OR CommandLine LIKE '%Cookies%' OR CommandLine LIKE '%Login Data%')))
