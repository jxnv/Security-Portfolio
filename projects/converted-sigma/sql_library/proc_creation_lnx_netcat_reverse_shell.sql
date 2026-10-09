-- Title: Potential Netcat Reverse Shell Execution
-- ID: 7f734ed0-4f47-46c0-837f-6ee62505abd9
-- Status: test
-- Level: high
-- Author: @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-07
-- Tags: attack.execution, attack.t1059
-- Description: Detects execution of netcat with the "-e" or "-c" flags followed by common shells, which are commonly used to spawn reverse shells.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% -c %' OR CommandLine ILIKE '% -e %')) AND ((Image ILIKE '%/nc.openbsd' OR Image ILIKE '%/nc.traditional' OR Image ILIKE '%/nc' OR Image ILIKE '%/ncat' OR Image ILIKE '%/netcat.openbsd' OR Image ILIKE '%/netcat.traditional' OR Image ILIKE '%/netcat')) AND ((CommandLine ILIKE '% ash%' OR CommandLine ILIKE '% bash%' OR CommandLine ILIKE '% bsh%' OR CommandLine ILIKE '% csh%' OR CommandLine ILIKE '% ksh%' OR CommandLine ILIKE '% pdksh%' OR CommandLine ILIKE '% sh%' OR CommandLine ILIKE '% tcsh%' OR CommandLine ILIKE '%/bin/ash%' OR CommandLine ILIKE '%/bin/bash%' OR CommandLine ILIKE '%/bin/bsh%' OR CommandLine ILIKE '%/bin/csh%' OR CommandLine ILIKE '%/bin/ksh%' OR CommandLine ILIKE '%/bin/pdksh%' OR CommandLine ILIKE '%/bin/sh%' OR CommandLine ILIKE '%/bin/tcsh%' OR CommandLine ILIKE '%/bin/zsh%' OR CommandLine ILIKE '%$IFSash%' OR CommandLine ILIKE '%$IFSbash%' OR CommandLine ILIKE '%$IFSbsh%' OR CommandLine ILIKE '%$IFScsh%' OR CommandLine ILIKE '%$IFSksh%' OR CommandLine ILIKE '%$IFSpdksh%' OR CommandLine ILIKE '%$IFSsh%' OR CommandLine ILIKE '%$IFStcsh%' OR CommandLine ILIKE '%$IFSzsh%')))
