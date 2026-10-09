-- Title: Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call
-- ID: 9c0295ce-d60d-40bd-bd74-84673b7592b1
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems)
-- Date: 2022-03-01
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027
-- Description: Detects suspicious base64 encoded and obfuscated "LOAD" keyword used in .NET "reflection.assembly"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ%' OR CommandLine LIKE '%oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA%' OR CommandLine LIKE '%6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA%' OR CommandLine LIKE '%OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ%' OR CommandLine LIKE '%oAOgAoACIATABvACIAKwAiAGEAZAAiACkA%' OR CommandLine LIKE '%6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA%' OR CommandLine LIKE '%OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ%' OR CommandLine LIKE '%oAOgAoACIATABvAGEAIgArACIAZAAiACkA%' OR CommandLine LIKE '%6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA%' OR CommandLine LIKE '%OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ%' OR CommandLine LIKE '%oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA%' OR CommandLine LIKE '%6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA%' OR CommandLine LIKE '%OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ%' OR CommandLine LIKE '%oAOgAoACcATABvACcAKwAnAGEAZAAnACkA%' OR CommandLine LIKE '%6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA%' OR CommandLine LIKE '%OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ%' OR CommandLine LIKE '%oAOgAoACcATABvAGEAJwArACcAZAAnACkA%' OR CommandLine LIKE '%6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA%'))
