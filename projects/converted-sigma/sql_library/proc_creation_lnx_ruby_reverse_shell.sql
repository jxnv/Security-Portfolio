-- Title: Potential Ruby Reverse Shell
-- ID: b8bdac18-c06e-4016-ac30-221553e74f59
-- Status: test
-- Level: medium
-- Author: @d4ns4n_
-- Date: 2023-04-07
-- Tags: attack.execution
-- Description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%ruby%' AND (CommandLine ILIKE '% -e%' AND CommandLine ILIKE '%rsocket%' AND CommandLine ILIKE '%TCPSocket%') AND (CommandLine ILIKE '% ash%' OR CommandLine ILIKE '% bash%' OR CommandLine ILIKE '% bsh%' OR CommandLine ILIKE '% csh%' OR CommandLine ILIKE '% ksh%' OR CommandLine ILIKE '% pdksh%' OR CommandLine ILIKE '% sh%' OR CommandLine ILIKE '% tcsh%'))
