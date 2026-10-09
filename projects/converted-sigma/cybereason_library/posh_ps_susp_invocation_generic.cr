// Title: Suspicious PowerShell Invocations - Generic
// ID: ed965133-513f-41d9-a441-e38076a0798f
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2017-03-12
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious PowerShell invocation command parameters
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText contains " -enc " OR ScriptBlockText contains " -EncodedCommand " OR ScriptBlockText contains " -ec ")) AND ((ScriptBlockText contains " -w hidden " OR ScriptBlockText contains " -window hidden " OR ScriptBlockText contains " -windowstyle hidden " OR ScriptBlockText contains " -w 1 ")) AND ((ScriptBlockText contains " -noni " OR ScriptBlockText contains " -noninteractive ")))
