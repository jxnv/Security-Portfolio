// Title: Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call
// ID: 9c0295ce-d60d-40bd-bd74-84673b7592b1
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2022-03-01
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027
// Description: Detects suspicious base64 encoded and obfuscated "LOAD" keyword used in .NET "reflection.assembly"
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ*" OR CommandLine: "*oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA*" OR CommandLine: "*6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA*" OR CommandLine: "*OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ*" OR CommandLine: "*oAOgAoACIATABvACIAKwAiAGEAZAAiACkA*" OR CommandLine: "*6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA*" OR CommandLine: "*OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ*" OR CommandLine: "*oAOgAoACIATABvAGEAIgArACIAZAAiACkA*" OR CommandLine: "*6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA*" OR CommandLine: "*OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ*" OR CommandLine: "*oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA*" OR CommandLine: "*6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA*" OR CommandLine: "*OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ*" OR CommandLine: "*oAOgAoACcATABvACcAKwAnAGEAZAAnACkA*" OR CommandLine: "*6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA*" OR CommandLine: "*OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ*" OR CommandLine: "*oAOgAoACcATABvAGEAJwArACcAZAAnACkA*" OR CommandLine: "*6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA*"))
