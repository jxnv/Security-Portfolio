-- Title: Antivirus - Web Shell Detection Signature
-- ID: fdf135a2-9241-4f96-a114-bb404948f736
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Arnim Rupp
-- Date: 2018-09-09
-- Tags: attack.persistence, attack.t1505.003
-- Description: Detects a highly relevant Antivirus alert that reports a web shell.
-- It's highly recommended to tune this rule to the specific strings used by your anti virus solution by downloading a big WebShell repository from e.g. github and checking the matches.
-- This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Signature ILIKE 'ASP.%' OR Signature ILIKE 'IIS/BackDoor%' OR Signature ILIKE 'JAVA/Backdoor%' OR Signature ILIKE 'JSP.%' OR Signature ILIKE 'Perl.%' OR Signature ILIKE 'PHP.%' OR Signature ILIKE 'Troj/ASP%' OR Signature ILIKE 'Troj/JSP%' OR Signature ILIKE 'Troj/PHP%' OR Signature ILIKE 'VBS/Uxor%')) OR ((Signature ILIKE '%ASP_%' OR Signature ILIKE '%ASP:%' OR Signature ILIKE '%ASP.Agent%' OR Signature ILIKE '%ASP/%' OR Signature ILIKE '%Aspdoor%' OR Signature ILIKE '%ASPXSpy%' OR Signature ILIKE '%Backdoor.ASP%' OR Signature ILIKE '%Backdoor.Java%' OR Signature ILIKE '%Backdoor.JSP%' OR Signature ILIKE '%Backdoor.PHP%' OR Signature ILIKE '%Backdoor.VBS%' OR Signature ILIKE '%Backdoor/ASP%' OR Signature ILIKE '%Backdoor/Java%' OR Signature ILIKE '%Backdoor/JSP%' OR Signature ILIKE '%Backdoor/PHP%' OR Signature ILIKE '%Backdoor/VBS%' OR Signature ILIKE '%C99shell%' OR Signature ILIKE '%Chopper%' OR Signature ILIKE '%filebrowser%' OR Signature ILIKE '%JSP_%' OR Signature ILIKE '%JSP:%' OR Signature ILIKE '%JSP.Agent%' OR Signature ILIKE '%JSP/%' OR Signature ILIKE '%Perl:%' OR Signature ILIKE '%Perl/%' OR Signature ILIKE '%PHP_%' OR Signature ILIKE '%PHP:%' OR Signature ILIKE '%PHP.Agent%' OR Signature ILIKE '%PHP/%' OR Signature ILIKE '%PHPShell%' OR Signature ILIKE '%PShlSpy%' OR Signature ILIKE '%SinoChoper%' OR Signature ILIKE '%Trojan.ASP%' OR Signature ILIKE '%Trojan.JSP%' OR Signature ILIKE '%Trojan.PHP%' OR Signature ILIKE '%Trojan.VBS%' OR Signature ILIKE '%VBS.Agent%' OR Signature ILIKE '%VBS/Agent%' OR Signature ILIKE '%Webshell%')))
