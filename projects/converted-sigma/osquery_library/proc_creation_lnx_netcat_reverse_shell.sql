-- Title: Potential Netcat Reverse Shell Execution
-- ID: 7f734ed0-4f47-46c0-837f-6ee62505abd9
-- Status: test
-- Level: high
-- Author: @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-07
-- Tags: attack.execution, attack.t1059
-- Description: Detects execution of netcat with the "-e" or "-c" flags followed by common shells, which are commonly used to spawn reverse shells.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -c %' OR CommandLine LIKE '% -e %')) AND ((Image="*/nc.openbsd" OR Image="*/nc.traditional" OR Image="*/nc" OR Image="*/ncat" OR Image="*/netcat.openbsd" OR Image="*/netcat.traditional" OR Image="*/netcat")) AND ((CommandLine LIKE '% ash%' OR CommandLine LIKE '% bash%' OR CommandLine LIKE '% bsh%' OR CommandLine LIKE '% csh%' OR CommandLine LIKE '% ksh%' OR CommandLine LIKE '% pdksh%' OR CommandLine LIKE '% sh%' OR CommandLine LIKE '% tcsh%' OR CommandLine LIKE '%/bin/ash%' OR CommandLine LIKE '%/bin/bash%' OR CommandLine LIKE '%/bin/bsh%' OR CommandLine LIKE '%/bin/csh%' OR CommandLine LIKE '%/bin/ksh%' OR CommandLine LIKE '%/bin/pdksh%' OR CommandLine LIKE '%/bin/sh%' OR CommandLine LIKE '%/bin/tcsh%' OR CommandLine LIKE '%/bin/zsh%' OR CommandLine LIKE '%$IFSash%' OR CommandLine LIKE '%$IFSbash%' OR CommandLine LIKE '%$IFSbsh%' OR CommandLine LIKE '%$IFScsh%' OR CommandLine LIKE '%$IFSksh%' OR CommandLine LIKE '%$IFSpdksh%' OR CommandLine LIKE '%$IFSsh%' OR CommandLine LIKE '%$IFStcsh%' OR CommandLine LIKE '%$IFSzsh%')))
