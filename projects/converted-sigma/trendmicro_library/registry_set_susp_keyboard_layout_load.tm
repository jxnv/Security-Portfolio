// Title: Suspicious Keyboard Layout Load
// ID: 34aa0252-6039-40ff-951f-939fd6ce47d8
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2019-10-12
// Tags: attack.resource-development, attack.t1588.002
// Description: Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject: "*\\Keyboard Layout\\Preload\\*" OR TargetObject: "*\\Keyboard Layout\\Substitutes\\*") AND (Details: "*00000429*" OR Details: "*00050429*" OR Details: "*0000042a*"))
