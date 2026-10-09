// Title: Antivirus - Web Shell Detection Signature
// ID: fdf135a2-9241-4f96-a114-bb404948f736
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Arnim Rupp
// Date: 2018-09-09
// Tags: attack.persistence, attack.t1505.003
// Description: Detects a highly relevant Antivirus alert that reports a web shell.
// It's highly recommended to tune this rule to the specific strings used by your anti virus solution by downloading a big WebShell repository from e.g. github and checking the matches.
// This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Signature="ASP.*" OR Signature="IIS/BackDoor*" OR Signature="JAVA/Backdoor*" OR Signature="JSP.*" OR Signature="Perl.*" OR Signature="PHP.*" OR Signature="Troj/ASP*" OR Signature="Troj/JSP*" OR Signature="Troj/PHP*" OR Signature="VBS/Uxor*")) OR ((Signature contains "ASP_" OR Signature contains "ASP:" OR Signature contains "ASP.Agent" OR Signature contains "ASP/" OR Signature contains "Aspdoor" OR Signature contains "ASPXSpy" OR Signature contains "Backdoor.ASP" OR Signature contains "Backdoor.Java" OR Signature contains "Backdoor.JSP" OR Signature contains "Backdoor.PHP" OR Signature contains "Backdoor.VBS" OR Signature contains "Backdoor/ASP" OR Signature contains "Backdoor/Java" OR Signature contains "Backdoor/JSP" OR Signature contains "Backdoor/PHP" OR Signature contains "Backdoor/VBS" OR Signature contains "C99shell" OR Signature contains "Chopper" OR Signature contains "filebrowser" OR Signature contains "JSP_" OR Signature contains "JSP:" OR Signature contains "JSP.Agent" OR Signature contains "JSP/" OR Signature contains "Perl:" OR Signature contains "Perl/" OR Signature contains "PHP_" OR Signature contains "PHP:" OR Signature contains "PHP.Agent" OR Signature contains "PHP/" OR Signature contains "PHPShell" OR Signature contains "PShlSpy" OR Signature contains "SinoChoper" OR Signature contains "Trojan.ASP" OR Signature contains "Trojan.JSP" OR Signature contains "Trojan.PHP" OR Signature contains "Trojan.VBS" OR Signature contains "VBS.Agent" OR Signature contains "VBS/Agent" OR Signature contains "Webshell")))
