-- Title: Potential Product Class Reconnaissance Via Wmic.EXE
-- ID: e568650b-5dcd-4658-8f34-ded0b1e13992
-- Status: test
-- Level: medium
-- Author: Michael Haag, Florian Roth (Nextron Systems), juju4, oscd.community, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2023-02-14
-- Tags: attack.execution, attack.t1047, attack.discovery, attack.t1082
-- Description: Detects the execution of WMIC in order to get a list of firewall, antivirus and antispywware products.
-- Adversaries often enumerate security products installed on a system to identify security controls and potential ways to evade detection or disable protection mechanisms.
-- This information helps them plan their next attack steps and choose appropriate techniques to bypass security measures.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%AntiVirusProduct%' OR CommandLine ILIKE '%AntiSpywareProduct%' OR CommandLine ILIKE '%FirewallProduct%')) AND ((Image ILIKE '%\\wmic.exe') OR (OriginalFileName = 'wmic.exe')))
