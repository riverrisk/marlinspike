#ifndef MyAppName
#define MyAppName "MarlinSpike"
#endif
#ifndef MyAppVersion
#define MyAppVersion "2.0.0"
#endif
#ifndef MyAppPublisher
#define MyAppPublisher "RiverRisk"
#endif
#ifndef MyAppURL
#define MyAppURL "https://marlinspike.riverrisk.io/"
#endif
#ifndef MyAppExeName
#define MyAppExeName "runtime\\open-marlinspike.ps1"
#endif

[Setup]
AppId={{9A0E3D06-77FA-4A91-9D13-54AE2F08862E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\MarlinSpike
DefaultGroupName=MarlinSpike
LicenseFile=..\..\LICENSE
OutputDir=..\build\installer
OutputBaseFilename=MarlinSpike-Setup
Compression=lzma2
SolidCompression=yes
CompressionThreads=auto
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
UninstallDisplayIcon={sys}\WindowsPowerShell\v1.0\powershell.exe
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Dirs]
Name: "{localappdata}\MarlinSpike"; Permissions: users-modify
Name: "{localappdata}\MarlinSpike\data"; Permissions: users-modify
Name: "{localappdata}\MarlinSpike\logs"; Permissions: users-modify
Name: "{localappdata}\MarlinSpike\run"; Permissions: users-modify

[Files]
Source: "..\build\bundle\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Open MarlinSpike"; Filename: "{cmd}"; Parameters: "/c ""{app}\runtime\open-marlinspike.cmd"""; WorkingDir: "{app}"
Name: "{group}\Run MarlinSpike"; Filename: "{cmd}"; Parameters: "/c ""{app}\runtime\run-marlinspike.cmd"""; WorkingDir: "{app}"
Name: "{group}\Install Wireshark (Official)"; Filename: "{cmd}"; Parameters: "/c ""{app}\runtime\install-wireshark.cmd"""; WorkingDir: "{app}"
Name: "{group}\Stop MarlinSpike"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\runtime\stop-marlinspike.ps1"""; WorkingDir: "{app}"
Name: "{group}\Uninstall MarlinSpike"; Filename: "{uninstallexe}"
Name: "{autodesktop}\MarlinSpike"; Filename: "{cmd}"; Parameters: "/c ""{app}\runtime\open-marlinspike.cmd"""; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{cmd}"; Parameters: "/c ""{app}\runtime\install-wireshark.cmd"""; WorkingDir: "{app}"; Description: "Open official Wireshark download page (required for scans)"; Flags: postinstall skipifsilent unchecked; Check: not HasWireshark
Filename: "{cmd}"; Parameters: "/c ""{app}\runtime\open-marlinspike.cmd"""; WorkingDir: "{app}"; Description: "Launch MarlinSpike"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\runtime\stop-marlinspike.ps1"""; WorkingDir: "{app}"; Flags: runhidden

[Code]
function HasWireshark(): Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{pf}\Wireshark\tshark.exe')) or
    FileExists(ExpandConstant('{pf32}\Wireshark\tshark.exe'));
end;

procedure InitializeWizard;
begin
  if not HasWireshark() then
    SuppressibleMsgBox(
      'Wireshark CLI tools were not detected. MarlinSpike needs tshark, capinfos, and editcap installed on Windows to analyze captures. You can finish installing MarlinSpike now, then use the post-install checkbox or the Start Menu shortcut to open the official Wireshark download page.',
      mbInformation, MB_OK, IDOK);
end;
