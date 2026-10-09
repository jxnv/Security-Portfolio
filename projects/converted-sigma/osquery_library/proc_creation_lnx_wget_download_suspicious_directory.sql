-- Title: Download File To Potentially Suspicious Directory Via Wget
-- ID: cf610c15-ed71-46e1-bdf8-2bd1a99de6c4
-- Status: test
-- Level: medium
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2023-06-02
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects the use of wget to download content to a suspicious directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/wget") AND ((CommandLine=regex("\\s-O\\s")) OR (CommandLine LIKE '%--output-document%')) AND (CommandLine LIKE '%/tmp/%'))
