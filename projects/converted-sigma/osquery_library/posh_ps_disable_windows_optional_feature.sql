-- Title: Disable-WindowsOptionalFeature Command PowerShell
-- ID: 99c4658d-2c5e-4d87-828d-7c066ca537c3
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-09-10
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detect built in PowerShell cmdlet Disable-WindowsOptionalFeature, Deployment Image Servicing and Management tool.
-- Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%Disable-WindowsOptionalFeature%' AND ScriptBlockText LIKE '%-Online%' AND ScriptBlockText LIKE '%-FeatureName%')) AND ((ScriptBlockText LIKE '%Windows-Defender-Gui%' OR ScriptBlockText LIKE '%Windows-Defender-Features%' OR ScriptBlockText LIKE '%Windows-Defender%' OR ScriptBlockText LIKE '%Windows-Defender-ApplicationGuard%')))
