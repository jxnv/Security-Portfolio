-- Title: Hacktool - EDR-Freeze Execution
-- ID: c598cc0c-9e70-4852-b9eb-8921af79f598
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-09-24
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects execution of EDR-Freeze, a tool that exploits the MiniDumpWriteDump function and WerFaultSecure.exe to suspend EDR and Antivirus processes on Windows.
-- EDR-Freeze leverages a race-condition attack to put security processes into a dormant state by suspending WerFaultSecure at the moment it freezes the target process.
-- This technique does not require kernel-level exploits or BYOVD, but instead abuses user-mode functionality to temporarily disable monitoring by EDR or Antimalware solutions.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\EDR-Freeze%' OR Image ILIKE '%\\EDRFreeze%') AND Image ILIKE '%.exe') OR ((Hashes ILIKE '%IMPHASH=1195F7935954A2CD09157390C33F8E8C%' OR Hashes ILIKE '%IMPHASH=129F58DE3D687FB7F012BF6C3D679997%' OR Hashes ILIKE '%IMPHASH=2C617A175D0086251642C6619F7CC8BA%' OR Hashes ILIKE '%IMPHASH=8828F0B906F7844358FB92A899E9520F%' OR Hashes ILIKE '%IMPHASH=AF76D95157EC554DC1EF178E4E66D447%' OR Hashes ILIKE '%IMPHASH=E1B04316B61ACA31DD52ABBEC0A37FD5%' OR Hashes ILIKE '%IMPHASH=8B2D5B54AFCFEC60D54F6B31D80ED4A0%' OR Hashes ILIKE '%IMPHASH=AB8BB31EDD91D2A05FE7B62A535E9EB7%')))
