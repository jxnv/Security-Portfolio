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

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\where.exe') OR (OriginalFileName = 'where.exe')) AND ((CommandLine ILIKE '%places.sqlite%' OR CommandLine ILIKE '%cookies.sqlite%' OR CommandLine ILIKE '%formhistory.sqlite%' OR CommandLine ILIKE '%logins.json%' OR CommandLine ILIKE '%key4.db%' OR CommandLine ILIKE '%key3.db%' OR CommandLine ILIKE '%sessionstore.jsonlz4%' OR CommandLine ILIKE '%History%' OR CommandLine ILIKE '%Bookmarks%' OR CommandLine ILIKE '%Cookies%' OR CommandLine ILIKE '%Login Data%')))
