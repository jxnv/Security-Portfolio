-- Title: Python One-Liners with Base64 Decoding
-- ID: 50a0aa3d-ab16-4594-a8aa-5145a6e6792b
-- Status: experimental
-- Level: high
-- Author: Hugh Ryan (HueCodes), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-03-09
-- Tags: attack.execution, attack.stealth, attack.t1059.006, attack.t1027.010
-- Description: Detects Python one-liners that use base64 decoding functions in command line executions.
-- Malicious scripts or attackers often use python one-liners to decode and execute base64-encoded payloads, which is a common technique for obfuscation and evasion.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%import%' AND CommandLine ILIKE '%base64%' AND CommandLine ILIKE '% -c%') AND (CommandLine ILIKE '%.decode%' OR CommandLine ILIKE '%b16decode%' OR CommandLine ILIKE '%b32decode%' OR CommandLine ILIKE '%b32hexdecode%' OR CommandLine ILIKE '%b64decode%' OR CommandLine ILIKE '%b85decode%' OR CommandLine ILIKE '%z85decode%')) AND ((Image ILIKE '%\\python%') OR (OriginalFileName ILIKE '%python%')))
