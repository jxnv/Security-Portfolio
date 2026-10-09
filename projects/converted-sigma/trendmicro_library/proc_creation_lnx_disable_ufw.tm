// Title: UFW Disable Attempt
// ID: 84c9e83c-599a-458a-a0cb-0ecce44e807a
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-01-18
// Tags: attack.defense-impairment, attack.t1686
// Description: Detects attempts to disable the Uncomplicated Firewall (UFW) on Linux systems.
// UFW is a popular firewall management tool that provides an easy-to-use interface for configuring firewall rules.
// Disabling UFW can leave a system vulnerable to attacks, as it may allow unauthorized access to network services and resources.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*ufw *" AND CommandLine: "*disable*")) OR (Image="*/ufw-init" AND (CommandLine: "* force-stop*" OR CommandLine: "* stop*" OR CommandLine: "* flush*")))
