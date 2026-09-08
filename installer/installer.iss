; Miharu — Inno Setup 6
; Canonical script used by build\build.ps1

#define MyAppName "Miharu"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "Miharu"
#define MyAppExeName "Miharu.exe"
#define MyAppId "{{B7E4C1A2-8F3D-4E9A-9C2B-1A5D6E7F8091}"
#define LegacyAppId1 "{{12345678-ABCD-1234-ABCD-123456789ABC}"
#define LegacyAppId2 "{{D8A2C3C7-9E7A-4B52-9A1B-6D9B3A4F2E11}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppVerName={#MyAppName} {#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes
OutputDir=..\release
OutputBaseFilename=Miharu-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\assets\logo.ico
WizardSmallImageFile=..\assets\wizard_small.bmp
WizardImageFile=..\assets\wizard.bmp
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes
UsePreviousGroup=yes

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Ярлыки:"; Flags: unchecked

[Files]
Source: "..\dist\Miharu\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Удалить {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить Miharu"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function GetUninstallCmd(AppId: String): String;
var
  Uninstall: String;
  Key1, Key2, Key3: String;
begin
  Result := '';
  Key1 := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + AppId + '_is1';
  Key2 := 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' + AppId + '_is1';
  Key3 := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + AppId + '_is1';
  Uninstall := '';
  if RegQueryStringValue(HKLM, Key1, 'UninstallString', Uninstall) then
  begin
    Result := Uninstall;
    Exit;
  end;
  if RegQueryStringValue(HKLM, Key2, 'UninstallString', Uninstall) then
  begin
    Result := Uninstall;
    Exit;
  end;
  if RegQueryStringValue(HKCU, Key3, 'UninstallString', Uninstall) then
  begin
    Result := Uninstall;
    Exit;
  end;
end;

procedure TryUninstallLegacy(AppId: String; DisplayName: String);
var
  Cmd: String;
  ResultCode: Integer;
begin
  Cmd := GetUninstallCmd(AppId);
  if Cmd = '' then
    Exit;
  Cmd := RemoveQuotes(Cmd);
  Log('Uninstalling legacy ' + DisplayName + ': ' + Cmd);
  Exec(Cmd, '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  NeedsRestart := False;
  Result := '';
  TryUninstallLegacy('{#LegacyAppId1}', 'Disk Diagnostic legacy 1');
  TryUninstallLegacy('{#LegacyAppId2}', 'Disk Diagnostic legacy 2');
end;