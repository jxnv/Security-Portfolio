-- Title: Potential Suspicious PowerShell Keywords
-- ID: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Perez Diego (@darkquassar), Tuan Le (NCSGroup)
-- Date: 2019-02-11
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects potentially suspicious keywords that could indicate the use of a PowerShell exploitation framework
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%System.Reflection.Assembly.Load($%' OR ScriptBlockText ILIKE '%[System.Reflection.Assembly]::Load($%' OR ScriptBlockText ILIKE '%[Reflection.Assembly]::Load($%' OR ScriptBlockText ILIKE '%System.Reflection.AssemblyName%' OR ScriptBlockText ILIKE '%Reflection.Emit.AssemblyBuilderAccess%' OR ScriptBlockText ILIKE '%Reflection.Emit.CustomAttributeBuilder%' OR ScriptBlockText ILIKE '%Runtime.InteropServices.UnmanagedType%' OR ScriptBlockText ILIKE '%Runtime.InteropServices.DllImportAttribute%' OR ScriptBlockText ILIKE '%SuspendThread%' OR ScriptBlockText ILIKE '%rundll32%'))
