// Title: Suspicious PowerShell Invocations - Generic - PowerShell Module
// ID: bbb80e91-5746-4fbe-8898-122e2cafdbf4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2017-03-12
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious PowerShell invocation command parameters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ContextInfo contains " -enc " or ContextInfo contains " -EncodedCommand " or ContextInfo contains " -ec ")) and ((ContextInfo contains " -w hidden " or ContextInfo contains " -window hidden " or ContextInfo contains " -windowstyle hidden " or ContextInfo contains " -w 1 ")) and ((ContextInfo contains " -noni " or ContextInfo contains " -noninteractive ")))
