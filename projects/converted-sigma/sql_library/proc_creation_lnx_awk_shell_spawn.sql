-- Title: Suspicious Invocation of Shell via AWK - Linux
-- ID: 8c1a5675-cb85-452f-a298-b01b22a51856
-- Status: test
-- Level: high
-- Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date: 2024-09-02
-- Tags: attack.execution, attack.t1059
-- Description: Detects the execution of "awk" or it's sibling commands, to invoke a shell using the system() function.
-- This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%/bin/bash%' OR CommandLine ILIKE '%/bin/dash%' OR CommandLine ILIKE '%/bin/fish%' OR CommandLine ILIKE '%/bin/sh%' OR CommandLine ILIKE '%/bin/zsh%')) AND ((Image ILIKE '%/awk' OR Image ILIKE '%/gawk' OR Image ILIKE '%/mawk' OR Image ILIKE '%/nawk') AND CommandLine ILIKE '%BEGIN {system%'))
