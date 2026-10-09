-- Title: Bad Opsec Defaults Sacrificial Processes With Improper Arguments
-- ID: a7c3d773-caef-227e-a7e7-c2f13c622329
-- Status: test
-- Level: high
-- Author: Oleg Kolesnikov @securonix invrep_de, oscd.community, Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems)
-- Date: 2020-10-23
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects attackers using tooling with bad opsec defaults.
-- E.g. spawning a sacrificial process to inject a capability into the process without taking into account how the process is normally run.
-- One trivial example of this is using rundll32.exe without arguments as a sacrificial process (default in CS, now highlighted by c2lint), running WerFault without arguments (Kraken - credit am0nsec), and other examples.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\regasm.exe' AND CommandLine ILIKE '%regasm.exe') OR (Image ILIKE '%\\regsvcs.exe' AND CommandLine ILIKE '%regsvcs.exe') OR (Image ILIKE '%\\regsvr32.exe' AND CommandLine ILIKE '%regsvr32.exe') OR (Image ILIKE '%\\rundll32.exe' AND CommandLine ILIKE '%rundll32.exe') OR (Image ILIKE '%\\WerFault.exe' AND CommandLine ILIKE '%WerFault.exe')) AND NOT ((((ParentImage ILIKE '%\\AppData\\Local\\BraveSoftware\\Brave-Browser\\Application\\%' OR ParentImage ILIKE '%\\AppData\\Local\\Google\\Chrome\\Application\\%') AND ParentImage ILIKE '%\\Installer\\setup.exe' AND ParentCommandLine ILIKE '%--uninstall %' AND Image ILIKE '%\\rundll32.exe' AND CommandLine ILIKE '%rundll32.exe') OR (ParentImage ILIKE '%\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{%' AND Image ILIKE '%\\rundll32.exe' AND CommandLine ILIKE '%rundll32.exe'))))
