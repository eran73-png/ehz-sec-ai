; ============================================================
; FlowGuard â€” Inno Setup Script (MS8.2)
; AI Security Monitor for Claude Code | by EHZ-AI
; ============================================================

#define AppName    "FlowGuard"
#define AppVersion "2.4.0"
#define AppPublisher "FlowGuard"
#define AppURL     "https://ehz-server.duckdns.org"
#define SourceDir  "C:\Claude-Repo\agents\EHZ-SEC-AI"
#define OutputDir  "C:\Claude-Repo\agents\EHZ-SEC-AI\dist"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName=C:\FlowGuard
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir={#OutputDir}
OutputBaseFilename=FlowGuard-Setup-v{#AppVersion}
SetupIconFile={#SourceDir}\agent\flowguard.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardImageFile={#SourceDir}\agent\wizard-banner.bmp
WizardSmallImageFile={#SourceDir}\agent\wizard-small.bmp
PrivilegesRequired=admin
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\agent\flowguard.ico
UninstallDisplayName={#AppName} AI Security Monitor
MinVersion=10.0
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional icons:"
Name: "autostart"; Description: "Start FlowGuard automatically on &login (recommended)"; GroupDescription: "Startup:"

[Files]
; Core agent files
Source: "{#SourceDir}\agent\hook.js";              DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\tray.js";              DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\rules.js";             DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\flowguard.ico";        DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\whitelist.json";       DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\skill-registry.json";  DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\file-audit-scanner.js"; DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\domain-reputation.js"; DestDir: "{app}\agent"; Flags: ignoreversion
Source: "{#SourceDir}\agent\skill-scanner.js";     DestDir: "{app}\agent"; Flags: ignoreversion

; Collector
Source: "{#SourceDir}\collector\server.js";        DestDir: "{app}\collector"; Flags: ignoreversion

; Dashboard
Source: "{#SourceDir}\dashboard\*";               DestDir: "{app}\dashboard"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\docs\*";                   DestDir: "{app}\docs";      Flags: ignoreversion recursesubdirs createallsubdirs

; Scanner
Source: "{#SourceDir}\scanner\*";                 DestDir: "{app}\scanner"; Flags: ignoreversion recursesubdirs createallsubdirs

; Diagnostics tool (MS11)
Source: "{#SourceDir}\diag\*";                    DestDir: "{app}\diag";    Flags: ignoreversion recursesubdirs createallsubdirs

; Config
Source: "{#SourceDir}\config\*";                  DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs

; node_modules (all dependencies)
Source: "{#SourceDir}\node_modules\*";             DestDir: "{app}\node_modules"; Flags: ignoreversion recursesubdirs createallsubdirs

; Install scripts
Source: "{#SourceDir}\install\setup.ps1";           DestDir: "{app}\install"; Flags: ignoreversion
Source: "{#SourceDir}\install\autostart.ps1";       DestDir: "{app}\install"; Flags: ignoreversion
Source: "{#SourceDir}\install\install-service.ps1"; DestDir: "{app}\install"; Flags: ignoreversion
Source: "{#SourceDir}\install\uninstall.ps1";       DestDir: "{app}\install"; Flags: ignoreversion
Source: "{#SourceDir}\install\start-tray.vbs";     DestDir: "{app}\install"; Flags: ignoreversion

; NSSM â€” Windows Service Manager
Source: "{#SourceDir}\tools\nssm.exe";              DestDir: "{app}\tools";   Flags: ignoreversion

; package.json + README
Source: "{#SourceDir}\package.json";              DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md";                 DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\logs"
Name: "{app}\collector"

[Icons]
Name: "{group}\FlowGuard Dashboard";  Filename: "{app}\dashboard\index-v2.html"; IconFilename: "{app}\agent\flowguard.ico"
Name: "{group}\Uninstall FlowGuard"; Filename: "{uninstallexe}"
Name: "{userdesktop}\FlowGuard";      Filename: "{app}\dashboard\index-v2.html"; IconFilename: "{app}\agent\flowguard.ico"; Tasks: desktopicon
Name: "{userstartup}\FlowGuard Tray"; Filename: "{app}\install\start-tray.vbs"; IconFilename: "{app}\agent\flowguard.ico"; Tasks: autostart

[Run]
; 1. Run setup wizard (configure Telegram + hooks)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\install\setup.ps1"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Configuring FlowGuard..."

; 2. Install Windows Service (autostart)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\install\install-service.ps1"""; WorkingDir: "{app}\install"; Flags: runhidden waituntilterminated; Tasks: autostart; StatusMsg: "Installing FlowGuard as Windows Service..."

; 3. Start the service (ensure it's running after install)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -Command ""Start-Sleep 2; Start-Service FlowGuardCollector -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; Tasks: autostart; StatusMsg: "Starting FlowGuard..."

; 4. Launch Tray immediately after install
Filename: "wscript.exe"; Parameters: """{app}\install\start-tray.vbs"""; Flags: nowait runhidden; Tasks: autostart; StatusMsg: "Starting FlowGuard Tray..."

; 5. Open dashboard after install
Filename: "{app}\dashboard\index-v2.html"; Flags: postinstall nowait shellexec skipifsilent; Description: "Open FlowGuard Dashboard"

[UninstallRun]
; Remove Windows Service
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -File ""{app}\install\install-service.ps1"" -Remove"; \
  Flags: runhidden waituntilterminated

; Remove hooks from Claude settings.json
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -File ""{app}\install\setup.ps1"" -Uninstall"; \
  Flags: runhidden waituntilterminated

[Code]
// Check Node.js before install
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if not Exec('node', '--version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if MsgBox(
      'Node.js is required but not found.' + #13#10 +
      'Please install Node.js v18 or later from https://nodejs.org/' + #13#10 + #13#10 +
      'Continue anyway?',
      mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;










