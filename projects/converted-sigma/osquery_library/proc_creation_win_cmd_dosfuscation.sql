-- Title: Potential Dosfuscation Activity
-- ID: a77c1610-fc73-4019-8e29-0f51efc04a51
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-02-15
-- Tags: attack.execution, attack.t1059
-- Description: Detects possible payload obfuscation via the commandline
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%^^%' OR CommandLine LIKE '%^|^%' OR CommandLine LIKE '%,;,%' OR CommandLine LIKE '%;;;;%' OR CommandLine LIKE '%;; ;;%' OR CommandLine LIKE '%(,(,%' OR CommandLine LIKE '%%COMSPEC:~%' OR CommandLine LIKE '% c^m^d%' OR CommandLine LIKE '%^c^m^d%' OR CommandLine LIKE '% c^md%' OR CommandLine LIKE '% cm^d%' OR CommandLine LIKE '%^cm^d%' OR CommandLine LIKE '% s^et %' OR CommandLine LIKE '% s^e^t %' OR CommandLine LIKE '% se^t %'))
