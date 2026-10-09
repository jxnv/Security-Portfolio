-- Title: HackTool - Empire UserAgent URI Combo
-- ID: b923f7d6-ac89-4a50-a71a-89fb846b4aa8
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2020-07-13
-- Tags: attack.command-and-control, attack.t1071.001
-- Description: Detects user agent and URI paths used by empire agents
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (c-useragent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko' AND (cs-uri = '/admin/get.php' OR cs-uri = '/news.php' OR cs-uri = '/login/process.php') AND cs-method = 'POST')
