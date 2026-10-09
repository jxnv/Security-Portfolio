-- Title: Esentutl Steals Browser Information
-- ID: 6a69f62d-ce75-4b57-8dce-6351eb55b362
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-13
-- Tags: attack.collection, attack.t1005
-- Description: One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-r%' OR CommandLine LIKE '%/r%')) AND ((Image="*\\esentutl.exe") OR (OriginalFileName = 'esentutl.exe')) AND (CommandLine LIKE '%\\Windows\\WebCache%'))
