// Title: Sysmon Configuration Modification
// ID: 1f2b5353-573f-4880-8e33-7d04dcf97744
// Status: test
// Level: high
// Author: frack113
// Date: 2021-06-04
// Tags: attack.stealth, attack.t1564
// Description: Detects when an attacker tries to hide from Sysmon by disabling or stopping it
// Converted by: Sigma Universal SIEM/EDR CLI

((("Sysmon config state changed") OR (State == "Stopped")) AND NOT ((State == "Started")))
