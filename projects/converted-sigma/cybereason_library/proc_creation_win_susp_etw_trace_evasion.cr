// Title: ETW Trace Evasion Activity
// ID: a238b5d0-ce2d-4414-a676-7a531b3d13d6
// Status: test
// Level: high
// Author: @neu5ron, Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
// Date: 2019-03-22
// Tags: attack.stealth, attack.defense-impairment, attack.t1070, attack.t1685, car.2016-04-002
// Description: Detects command line activity that tries to clear or disable any ETW trace log which could be a sign of logging evasion.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "cl" AND CommandLine contains "/Trace")) OR ((CommandLine contains "clear-log" AND CommandLine contains "/Trace")) OR ((CommandLine contains "sl" AND CommandLine contains "/e:false")) OR ((CommandLine contains "set-log" AND CommandLine contains "/e:false")) OR ((CommandLine contains "logman" AND CommandLine contains "update" AND CommandLine contains "trace" AND CommandLine contains "--p" AND CommandLine contains "-ets")) OR (CommandLine contains "Remove-EtwTraceProvider") OR ((CommandLine contains "Set-EtwTraceProvider" AND CommandLine contains "0x11")))
