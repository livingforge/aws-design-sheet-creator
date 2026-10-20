# Earlier aws-design-sheet installations that install.ps1 removes before it installs.
#
# Dot-sourced by install.ps1. Three kinds are found:
#   - an existing .venv in the folder being installed;
#   - aws-design-review skill copies of an older version under the .claude, .agents,
#     .github and legacy .codex skill folders of this project and of the user profile
#     (copies of the same or a newer version are other hosts' installs and are kept);
#   - the aws-design-sheet package installed into the Python used for installation.
# Folders are moved to the Windows Recycle Bin, never deleted permanently. Every
# folder is checked first; one that would not fit in the Recycle Bin stops the
# installation before anything changes. The package is removed with pip uninstall.

$SkillName = "aws-design-review"
$PackageName = "aws-design-sheet"
$SkillHosts = @(".claude", ".agents", ".github", ".codex")

if (-not ("AwsDesignSheet.RecycleBin" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AwsDesignSheet {
    public static class RecycleBin {
        // FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT, plus
        // FOF_WANTNUKEWARNING so that Windows asks instead of silently deleting
        // something that does not fit in the Recycle Bin.
        const ushort Flags = 0x0040 | 0x0010 | 0x0400 | 0x0004 | 0x4000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct Operation64 {
            public IntPtr Window; public uint Function; public string From; public string To; public ushort Flags;
            [MarshalAs(UnmanagedType.Bool)] public bool Aborted; public IntPtr NameMappings; public string Title;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
        struct Operation32 {
            public IntPtr Window; public uint Function; public string From; public string To; public ushort Flags;
            [MarshalAs(UnmanagedType.Bool)] public bool Aborted; public IntPtr NameMappings; public string Title;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHFileOperationW")]
        static extern int Run64(ref Operation64 operation);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHFileOperationW")]
        static extern int Run32(ref Operation32 operation);

        // 0 when the folder was moved and no part of the operation was aborted.
        public static int Move(string path) {
            string from = path + "\0";  // the list ends with a second NUL added by marshalling
            if (IntPtr.Size == 8) {
                var operation = new Operation64 { Function = 3, From = from, Flags = Flags };
                int result = Run64(ref operation);
                return result != 0 ? result : (operation.Aborted ? -1 : 0);
            } else {
                var operation = new Operation32 { Function = 3, From = from, Flags = Flags };
                int result = Run32(ref operation);
                return result != 0 ? result : (operation.Aborted ? -1 : 0);
            }
        }
    }
}
"@
}

function Get-PackageVersion {
    param([string]$Root)
    $pyproject = Join-Path $Root "pyproject.toml"
    if (-not (Test-Path -LiteralPath $pyproject -PathType Leaf)) { return $null }
    $text = [System.IO.File]::ReadAllText($pyproject)
    if ($text -notmatch '(?m)^name\s*=\s*"aws-design-sheet"\s*$') { return $null }
    if ($text -match '(?m)^version\s*=\s*"(\d+(?:\.\d+){1,3})"\s*$') { return [version]$Matches[1] }
    return $null
}

function Get-SkillSearchRoots {
    # The project holding this copy (<project>\<host>\skills\aws-design-review), then the user profile.
    param([string]$PackageRoot)
    $roots = @()
    $skills = Split-Path -Parent $PackageRoot
    $hostFolder = Split-Path -Parent $skills
    if ((Split-Path -Leaf $PackageRoot) -eq $SkillName -and (Split-Path -Leaf $skills) -eq "skills" -and
            $SkillHosts -contains (Split-Path -Leaf $hostFolder)) {
        $roots += Split-Path -Parent $hostFolder
    }
    $roots += $HOME
    return $roots
}

function Get-PythonPackage {
    param([string]$Python)
    $ErrorActionPreference = "Continue"  # pip reports a missing package on stderr
    $lines = & $Python -m pip show $PackageName 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $lines) { return $null }
    $fields = @{}
    foreach ($line in $lines) {
        if ($line -match '^([^:]+):\s*(.*)$') { $fields[$Matches[1]] = $Matches[2] }
    }
    $editable = $fields["Editable project location"]
    return [pscustomobject]@{
        Version = $fields["Version"]
        Location = if ($editable) { $editable } else { $fields["Location"] }
        Editable = [bool]$editable
    }
}

function Find-EarlierInstallations {
    param([string]$PackageRoot, [version]$Version, [string]$Python)
    $found = New-Object System.Collections.Generic.List[object]
    $self = (Resolve-Path -LiteralPath $PackageRoot).ProviderPath.TrimEnd('\')
    $venv = Join-Path $self ".venv"
    if (Test-Path -LiteralPath $venv) {
        $found.Add([pscustomobject]@{ Kind = "Environment"; Path = $venv; Version = $null; Remove = $true
                                      Note = "existing environment of this copy" })
    }
    $seen = @{ ($self.ToLowerInvariant()) = $true }
    foreach ($root in Get-SkillSearchRoots $self) {
        foreach ($hostName in $SkillHosts) {
            $candidate = [System.IO.Path]::Combine($root, $hostName, "skills", $SkillName)
            if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
            $full = (Resolve-Path -LiteralPath $candidate).ProviderPath.TrimEnd('\')
            if ($seen.ContainsKey($full.ToLowerInvariant())) { continue }
            $seen[$full.ToLowerInvariant()] = $true
            $other = Get-PackageVersion $full
            $older = $null -ne $other -and $other -lt $Version
            $note = if ($null -eq $other) { "version unknown; kept" }
                    elseif ($older) { "older than $Version" }
                    else { "not older than $Version; kept" }
            $found.Add([pscustomobject]@{ Kind = "Skill copy"; Path = $full; Version = $other; Remove = $older; Note = $note })
        }
    }
    $package = Get-PythonPackage $Python
    if ($package) {
        $note = "installed into $Python; removed with pip uninstall" + $(if ($package.Editable) { " (source folder kept)" } else { "" })
        $found.Add([pscustomobject]@{ Kind = "Python package"; Path = $package.Location; Version = $package.Version
                                      Remove = $true; Note = $note })
    }
    return $found
}

function Show-EarlierInstallations {
    param($Items)
    foreach ($item in $Items) {
        $version = if ($item.Version) { " $($item.Version)" } else { "" }
        $mark = if ($item.Remove) { "remove" } else { "keep  " }
        Write-Host "  [$mark] $($item.Kind)$version - $($item.Path) ($($item.Note))"
    }
}

function Confirm-EarlierInstallationRemoval {
    param($Items, [switch]$Force)
    $all = @($Items)
    if (-not $all) { return }
    Write-Host "Earlier aws-design-sheet installations:"
    Show-EarlierInstallations $all
    if (-not @($all | Where-Object { $_.Remove })) { return }
    Write-Host "Folders marked remove go to the Recycle Bin; the Python package is removed with pip uninstall."
    if ($Force) { return }
    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) {
        throw "Earlier installations were found (listed above). Run again with -Force to remove them, or remove them yourself. Nothing was removed or installed."
    }
    $answer = Read-Host "Remove them and continue installing? [y/N]"
    if ($answer -notmatch '^(?i:y|yes)$') { throw "Cancelled. Nothing was removed or installed." }
}

function Get-RecycleBinCapacity {
    # Bytes one item may take in the Recycle Bin of the folder's drive, or $null without one.
    param([string]$Path)
    $drive = [System.IO.Path]::GetPathRoot($Path)
    if ($drive -notmatch '^[A-Za-z]:\\$') { return $null }
    $volume = Get-CimInstance Win32_Volume -Filter "DriveLetter='$($drive.Substring(0, 2))'"
    if (-not $volume -or $volume.DriveType -ne 3) { return $null }  # 3: local disk
    $id = [regex]::Match($volume.DeviceID, '\{[0-9A-Fa-f-]+\}').Value
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\$id"
    $settings = if ($id) { Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue } else { $null }
    if ($settings -and $settings.NukeOnDelete -eq 1) { return $null }
    if ($settings -and $settings.MaxCapacity) { return [int64]$settings.MaxCapacity * 1MB }
    return [int64]($volume.Capacity * 0.05)  # at most the Windows default for an unconfigured drive
}

function Get-FolderBytes {
    param([string]$Path)
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return [int64]0 }
    return [int64]$sum
}

function Remove-EarlierInstallations {
    param($Items, [string]$Python)
    $remove = @($Items | Where-Object { $_.Remove })
    if (-not $remove) { return }
    $folders = @($remove | Where-Object { $_.Kind -ne "Python package" })
    $packages = @($remove | Where-Object { $_.Kind -eq "Python package" })
    # Check everything before changing anything.
    $pythonPath = (& $Python -c "import sys; print(sys.executable)" | Select-Object -Last 1).Trim()
    foreach ($folder in $folders) {
        if ($pythonPath.StartsWith($folder.Path + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "The Python used for installation ($pythonPath) is inside $($folder.Path). Pass -Python with another interpreter. Nothing was removed."
        }
        $capacity = Get-RecycleBinCapacity $folder.Path
        if ($null -eq $capacity) {
            throw "$($folder.Path) is not on a local drive with the Recycle Bin enabled. Move or remove it yourself. Nothing was removed."
        }
        $bytes = Get-FolderBytes $folder.Path
        if ($bytes -ge $capacity) {
            throw "$($folder.Path) ($([math]::Round($bytes / 1MB)) MB) does not fit in the Recycle Bin ($([math]::Round($capacity / 1MB)) MB). Move or remove it yourself. Nothing was removed."
        }
    }
    foreach ($package in $packages) {
        & $Python -m pip uninstall --yes $PackageName
        if ($LASTEXITCODE -ne 0) { throw "pip uninstall $PackageName failed for $Python. No folder was removed." }
    }
    foreach ($folder in $folders) {
        $result = [AwsDesignSheet.RecycleBin]::Move($folder.Path)
        if ($result -ne 0 -or (Test-Path -LiteralPath $folder.Path)) {
            throw "Could not move $($folder.Path) to the Recycle Bin (code $result); a file may be in use. Close programs using it and run the installer again."
        }
        Write-Host "Moved to the Recycle Bin: $($folder.Path)"
    }
}
