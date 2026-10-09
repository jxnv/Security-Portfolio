-- Title: Potential Ruby Reverse Shell
-- ID: b8bdac18-c06e-4016-ac30-221553e74f59
-- Status: test
-- Level: medium
-- Author: @d4ns4n_
-- Date: 2023-04-07
-- Tags: attack.execution
-- Description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image LIKE '%ruby%' AND (CommandLine LIKE '% -e%' AND CommandLine LIKE '%rsocket%' AND CommandLine LIKE '%TCPSocket%') AND (CommandLine LIKE '% ash%' OR CommandLine LIKE '% bash%' OR CommandLine LIKE '% bsh%' OR CommandLine LIKE '% csh%' OR CommandLine LIKE '% ksh%' OR CommandLine LIKE '% pdksh%' OR CommandLine LIKE '% sh%' OR CommandLine LIKE '% tcsh%'))
