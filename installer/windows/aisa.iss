#ifndef AppSource
  #error AppSource must point to the PyInstaller output directory
#endif
#ifndef OutputDir
  #error OutputDir must be specified
#endif

[Setup]
AppId={{E0E2DE8F-5369-4B9D-B0A2-9A2F75CDAC64}
AppName=AISA Static Analysis
AppVersion=0.1.0
DefaultDirName={localappdata}\Programs\AISA
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
OutputDir={#OutputDir}
OutputBaseFilename=AISA-Setup-x64
Compression=lzma2
SolidCompression=yes
UninstallDisplayName=AISA Static Analysis

[Tasks]
Name: "addtopath"; Description: "Add AISA to the current user's PATH"

[Files]
Source: "{#AppSource}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Code]
const
  EnvironmentKey = 'Environment';
  AisaKey = 'Software\AISA Static Analysis';

function SamePathEntry(Entry, Directory: String): Boolean;
begin
  Result := CompareText(RemoveBackslashUnlessRoot(Trim(Entry)),
    RemoveBackslashUnlessRoot(Trim(Directory))) = 0;
end;

function ContainsPathEntry(PathValue, Directory: String): Boolean;
var
  Entry: String;
  Separator: Integer;
begin
  Result := False;
  while PathValue <> '' do begin
    Separator := Pos(';', PathValue);
    if Separator = 0 then begin
      Entry := PathValue;
      PathValue := '';
    end else begin
      Entry := Copy(PathValue, 1, Separator - 1);
      Delete(PathValue, 1, Separator);
    end;
    if SamePathEntry(Entry, Directory) then begin
      Result := True;
      exit;
    end;
  end;
end;

function WithoutPathEntry(PathValue, Directory: String): String;
var
  Entry: String;
  Separator: Integer;
begin
  Result := '';
  while PathValue <> '' do begin
    Separator := Pos(';', PathValue);
    if Separator = 0 then begin
      Entry := PathValue;
      PathValue := '';
    end else begin
      Entry := Copy(PathValue, 1, Separator - 1);
      Delete(PathValue, 1, Separator);
    end;
    if (Entry <> '') and not SamePathEntry(Entry, Directory) then begin
      if Result <> '' then Result := Result + ';';
      Result := Result + Entry;
    end;
  end;
end;

procedure UpdateUserPath(Directory: String; AddEntry: Boolean);
var
  PathValue: String;
begin
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', PathValue) then
    PathValue := '';
  if AddEntry then begin
    if ContainsPathEntry(PathValue, Directory) then exit;
    if PathValue <> '' then PathValue := PathValue + ';';
    PathValue := PathValue + Directory;
  end else begin
    if not ContainsPathEntry(PathValue, Directory) then exit;
    PathValue := WithoutPathEntry(PathValue, Directory);
  end;
  if not RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', PathValue) then
    RaiseException('Could not update the current user PATH.');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  OwnedPath, PathValue, InstallPath: String;
begin
  if CurStep <> ssPostInstall then exit;
  InstallPath := ExpandConstant('{app}');
  if RegQueryStringValue(HKCU, AisaKey, 'AddedPath', OwnedPath) and
    not SamePathEntry(OwnedPath, InstallPath) then begin
    UpdateUserPath(OwnedPath, False);
    RegDeleteValue(HKCU, AisaKey, 'AddedPath');
  end;
  if WizardIsTaskSelected('addtopath') then begin
    if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', PathValue) then
      PathValue := '';
    if not ContainsPathEntry(PathValue, InstallPath) then begin
      UpdateUserPath(InstallPath, True);
      if not RegWriteStringValue(HKCU, AisaKey, 'AddedPath', InstallPath) then begin
        UpdateUserPath(InstallPath, False);
        RaiseException('Could not record the AISA PATH entry.');
      end;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  OwnedPath: String;
begin
  if CurUninstallStep <> usUninstall then exit;
  if RegQueryStringValue(HKCU, AisaKey, 'AddedPath', OwnedPath) then begin
    UpdateUserPath(OwnedPath, False);
    RegDeleteValue(HKCU, AisaKey, 'AddedPath');
  end;
end;
