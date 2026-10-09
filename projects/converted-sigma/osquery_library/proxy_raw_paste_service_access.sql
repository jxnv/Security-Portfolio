-- Title: Raw Paste Service Access
-- ID: 5468045b-4fcc-4d1a-973c-c9c9578edacb
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-12-05
-- Tags: attack.command-and-control, attack.t1071.001, attack.t1102.001, attack.t1102.003
-- Description: Detects direct access to raw pastes in different paste services often used by malware in their second stages to download malicious code in encrypted or encoded form
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((c-uri LIKE '%.paste.ee/r/%' OR c-uri LIKE '%.pastebin.com/raw/%' OR c-uri LIKE '%.hastebin.com/raw/%' OR c-uri LIKE '%.ghostbin.co/paste/*/raw/%' OR c-uri LIKE '%pastetext.net/%' OR c-uri LIKE '%pastebin.pl/%' OR c-uri LIKE '%paste.ee/%'))
