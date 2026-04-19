' FlowGuard Tray Launcher — v2.4.1
' Dynamically finds FlowGuard install folder (works with ANY install path)
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
appDir    = fso.GetParentFolderName(scriptDir)
sh.CurrentDirectory = appDir
sh.Run "node agent\tray.js", 0, False
