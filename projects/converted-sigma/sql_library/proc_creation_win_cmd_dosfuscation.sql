-- Title: Potential Dosfuscation Activity
-- ID: a77c1610-fc73-4019-8e29-0f51efc04a51
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-02-15
-- Tags: attack.execution, attack.t1059
-- Description: Detects possible payload obfuscation via the commandline
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%^^%' OR CommandLine ILIKE '%^|^%' OR CommandLine ILIKE '%,;,%' OR CommandLine ILIKE '%;;;;%' OR CommandLine ILIKE '%;; ;;%' OR CommandLine ILIKE '%(,(,%' OR CommandLine ILIKE '%%COMSPEC:~%' OR CommandLine ILIKE '% c^m^d%' OR CommandLine ILIKE '%^c^m^d%' OR CommandLine ILIKE '% c^md%' OR CommandLine ILIKE '% cm^d%' OR CommandLine ILIKE '%^cm^d%' OR CommandLine ILIKE '% s^et %' OR CommandLine ILIKE '% s^e^t %' OR CommandLine ILIKE '% se^t %'))
