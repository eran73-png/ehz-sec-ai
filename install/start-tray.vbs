Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = "C:\FlowGuard"
sh.Run "node agent\tray.js", 0, False
