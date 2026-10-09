-- Title: Potential PHP Reverse Shell
-- ID: c6714a24-d7d5-4283-a36b-3ffd091d5f7e
-- Status: test
-- Level: high
-- Author: @d4ns4n_
-- Date: 2023-04-07
-- Tags: attack.execution
-- Description: Detects usage of the PHP CLI with the "-r" flag which allows it to run inline PHP code. The rule looks for calls to the "fsockopen" function which allows the creation of sockets.
-- Attackers often leverage this in combination with functions such as "exec" or "fopen" to initiate a reverse shell connection.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image LIKE '%/php%' AND (CommandLine LIKE '% -r %' AND CommandLine LIKE '%fsockopen%') AND (CommandLine LIKE '%ash%' OR CommandLine LIKE '%bash%' OR CommandLine LIKE '%bsh%' OR CommandLine LIKE '%csh%' OR CommandLine LIKE '%ksh%' OR CommandLine LIKE '%pdksh%' OR CommandLine LIKE '%sh%' OR CommandLine LIKE '%tcsh%' OR CommandLine LIKE '%zsh%'))
