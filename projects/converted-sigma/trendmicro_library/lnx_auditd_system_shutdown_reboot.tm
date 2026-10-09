// Title: System Shutdown/Reboot - Linux
// ID: 4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f
// Status: test
// Level: informational
// Author: Igor Fits, oscd.community
// Date: 2020-10-15
// Tags: attack.impact, attack.t1529
// Description: Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.
// Converted by: Sigma Universal SIEM/EDR CLI

((type: "EXECVE") AND (("shutdown" OR "reboot" OR "halt" OR "poweroff") OR (("init" OR "telinit") AND ("0" OR "6"))))
