; ============================================================
; FlowGuard â€” Inno Setup Script (MS8.2)
; AI Security Monitor for Claude Code | by EHZ-AI
; ============================================================

#define AppName    "FlowGuard"
#define AppVersion "2.6.7"
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
Source: "{#SourceDir}\agent\whitelist.json";       DestDir: "{app}\agent"; Flags: onlyifdoesntexist
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
Source: "{#SourceDir}\install\set-project-root.js"; DestDir: "{app}\install"; Flags: ignoreversion

; NSSM â€” Windows Service Manager
Source: "{#SourceDir}\tools\nssm.exe";              DestDir: "{app}\tools";   Flags: ignoreversion

; package.json + README
Source: "{#SourceDir}\package.json";              DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md";                 DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\logs"
Name: "{app}\collector"

[Icons]
Name: "{group}\FlowGuard Dashboard";  Filename: "http://localhost:3010/dashboard/index-v2.html"; IconFilename: "{app}\agent\flowguard.ico"
Name: "{group}\Uninstall FlowGuard"; Filename: "{uninstallexe}"
Name: "{userdesktop}\FlowGuard";      Filename: "http://localhost:3010/dashboard/index-v2.html"; IconFilename: "{app}\agent\flowguard.ico"; Tasks: desktopicon
Name: "{userstartup}\FlowGuard Tray"; Filename: "{app}\install\start-tray.vbs"; IconFilename: "{app}\agent\flowguard.ico"; Tasks: autostart

[Run]
; 1. Run setup wizard (configure Telegram + hooks)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\install\setup.ps1"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Configuring FlowGuard..."

; 2. Install Windows Service (autostart)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\install\install-service.ps1"""; WorkingDir: "{app}\install"; Flags: runhidden waituntilterminated; Tasks: autostart; StatusMsg: "Installing FlowGuard as Windows Service..."

; 3. Restart service fresh (stop old + start new with updated config)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -Command ""Stop-Service FlowGuardCollector -ErrorAction SilentlyContinue; Start-Sleep 2; Start-Service FlowGuardCollector -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; Tasks: autostart; StatusMsg: "Starting FlowGuard service..."

; 4. Launch Tray immediately after install
Filename: "wscript.exe"; Parameters: """{app}\install\start-tray.vbs"""; Flags: nowait runhidden; Tasks: autostart; StatusMsg: "Starting FlowGuard Tray..."

; 5. Open dashboard after install
Filename: "http://localhost:3010/dashboard/index-v2.html"; Flags: postinstall nowait shellexec skipifsilent; Description: "Open FlowGuard Dashboard"

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
var
  ProjectDirPage: TInputDirWizardPage;
  ProjectDir: String;

// Check Node.js + stop existing service before install
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  // Stop existing service so new config takes effect
  Exec('net', 'stop FlowGuardCollector', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Check Node.js
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

// Create custom wizard page for Project Directory
procedure InitializeWizard();
begin
  ProjectDirPage := CreateInputDirPage(wpSelectDir,
    'Select Project Directory',
    'Where is your code project located?',
    'FlowGuard will monitor this folder for file changes, security issues, and audit activity.' + #13#10 + #13#10 +
    'Select the root folder of your project (e.g. C:\MyProject or D:\Code):',
    False, '');
  ProjectDirPage.Add('');
  // Default to C:\ if no better option
  if DirExists('C:\Claude-Project') then
    ProjectDirPage.Values[0] := 'C:\Claude-Project'
  else if DirExists('C:\Projects') then
    ProjectDirPage.Values[0] := 'C:\Projects'
  else
    ProjectDirPage.Values[0] := 'C:\';
end;

// Validate — must select a real directory, not root drive
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ProjectDirPage.ID then
  begin
    ProjectDir := ProjectDirPage.Values[0];
    if (ProjectDir = '') or (ProjectDir = 'C:\') or (ProjectDir = 'D:\') then
    begin
      MsgBox('Please select a specific project folder, not a drive root.' + #13#10 +
             'Example: C:\MyProject or D:\Code',
             mbError, MB_OK);
      Result := False;
    end
    else if not DirExists(ProjectDir) then
    begin
      if MsgBox('The folder "' + ProjectDir + '" does not exist.' + #13#10 +
                'Create it now?',
                mbConfirmation, MB_YESNO) = IDYES then
      begin
        ForceDirectories(ProjectDir);
        Result := True;
      end
      else
        Result := False;
    end;
  end;
end;

// After install: write project_root to whitelist.json via Node.js (reliable JSON handling)
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  ScriptPath: String;
begin
  if CurStep = ssPostInstall then
  begin
    ProjectDir := ProjectDirPage.Values[0];
    ScriptPath := ExpandConstant('{app}\install\set-project-root.js');

    Exec('node', '"' + ScriptPath + '" "' + ProjectDir + '"',
         ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('FlowGuard: set-project-root.js exit code: ' + IntToStr(ResultCode) + ' | dir: ' + ProjectDir);

    if ResultCode <> 0 then
      MsgBox('Warning: Could not save project directory setting.' + #13#10 +
             'You can set it manually in Settings after installation.',
             mbInformation, MB_OK);
  end;
end;













