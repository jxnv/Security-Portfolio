// Title: FortiGate - New Firewall Policy Added
// ID: f24ab7a8-f09a-4319-82c1-915586aa642b
// Status: experimental
// Level: medium
// Author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
// Date: 2025-11-01
// Tags: attack.defense-impairment, attack.t1686.002
// Description: Detects the addition of a new firewall policy on a Fortinet FortiGate Firewall.
// Converted by: Sigma Universal SIEM/EDR CLI

(action == "Add" AND cfgpath == "firewall.policy")
