// Title: Changes To PIM Settings
// ID: db6c06c4-bf3b-421c-aa88-15672b88c743
// Status: test
// Level: high
// Author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
// Date: 2022-08-09
// Tags: attack.initial-access, attack.privilege-escalation, attack.persistence, attack.stealth, attack.t1078.004
// Description: Detects when changes are made to PIM roles
// Converted by: Sigma Universal SIEM/EDR CLI

(properties.message: "Update role setting in PIM")
