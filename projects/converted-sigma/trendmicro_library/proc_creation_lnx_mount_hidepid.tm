// Title: Mount Execution With Hidepid Parameter
// ID: ec52985a-d024-41e3-8ff6-14169039a0b3
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-01-12
// Tags: attack.credential-access, attack.stealth, attack.t1564
// Description: Detects execution of the "mount" command with "hidepid" parameter to make invisible processes to other users from the system
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*/mount" AND (CommandLine: "*hidepid=2*" AND CommandLine: "* -o *"))
