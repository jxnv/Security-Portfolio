-- Title: Potential COM Objects Download Cradles Usage - PS Script
-- ID: 3c7d1587-3b13-439f-9941-7d14313dbdfe
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-12-25
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects usage of COM objects that can be abused to download files in PowerShell by CLSID
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%[Type]::GetTypeFromCLSID(%') AND ((ScriptBlockText LIKE '%0002DF01-0000-0000-C000-000000000046%' OR ScriptBlockText LIKE '%F6D90F16-9C73-11D3-B32E-00C04F990BB4%' OR ScriptBlockText LIKE '%F5078F35-C551-11D3-89B9-0000F81FE221%' OR ScriptBlockText LIKE '%88d96a0a-f192-11d4-a65f-0040963251e5%' OR ScriptBlockText LIKE '%AFBA6B42-5692-48EA-8141-DC517DCF0EF1%' OR ScriptBlockText LIKE '%AFB40FFD-B609-40A3-9828-F88BBE11E4E3%' OR ScriptBlockText LIKE '%88d96a0b-f192-11d4-a65f-0040963251e5%' OR ScriptBlockText LIKE '%2087c2f4-2cef-4953-a8ab-66779b670495%' OR ScriptBlockText LIKE '%000209FF-0000-0000-C000-000000000046%' OR ScriptBlockText LIKE '%00024500-0000-0000-C000-000000000046%')))
