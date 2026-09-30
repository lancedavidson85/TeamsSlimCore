<#
.SYNOPSIS
    Microsoft Teams SlimCore / AVD Endpoint Diagnostic v5

.DESCRIPTION
    Read-only diagnostic for Microsoft Teams SlimCore on a physical
    Windows endpoint connecting to Azure Virtual Desktop or Windows 365.

    Checks:
      - Windows version
      - OS architecture
      - Physical memory
      - CPU cores
      - Windows App / Windows 365 package
      - Azure Virtual Desktop Host App
      - Active AVD client
      - Visual C++ Redistributables
      - MsTeamsPluginAvd.dll presence
      - MsTeamsPluginAvd.dll loaded state
      - SlimCore Framework packages
      - SlimCore Host package
      - Current Host / Framework version match
      - AppX / MSIX policies
      - SlimCore-specific AppX events
      - Duplicate SlimCore error event grouping
      - SlimCore deployment recovery
      - Microphone privacy
      - Camera privacy

    Creates:
      - SlimCore-Summary.txt
      - SlimCore-Results.csv
      - SlimCore-Packages.csv
      - SlimCore-AppX-Events.csv
      - SlimCore-AppX-Incidents.csv

.NOTES
    This script does not make configuration changes.

    Recommended:
      - Run from 64-bit PowerShell.
      - Run elevated.
      - Run while the affected AVD session is connected.
      - Run while Teams is showing the SlimCore problem.
#>

[CmdletBinding()]
param (
    [ValidateRange(1, 720)]
    [int]$EventLookbackHours = 48
)

# ============================================================
# Configuration
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

$MinimumWindowsBuild = 17763

$MinimumClientPackageVersion = [version]"2.0.352.0"

$MinimumRAMGB = 4

$MinimumCPUCores = 4

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$ReportFolder = Join-Path `
    -Path $env:TEMP `
    -ChildPath "Teams-SlimCore-Diagnostic-$env:COMPUTERNAME-$Timestamp"

New-Item `
    -Path $ReportFolder `
    -ItemType Directory `
    -Force |
    Out-Null

$Results = [System.Collections.Generic.List[object]]::new()

# ============================================================
# Function: Add-Check
# ============================================================

function Add-Check {

    param (
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [ValidateSet(
            "PASS",
            "FAIL",
            "WARN",
            "INFO"
        )]
        [string]$Status,

        [string]$Detected,

        [string]$Required,

        [string]$Notes
    )

    $Results.Add(
        [PSCustomObject]@{
            Category = $Category
            Check     = $Check
            Status    = $Status
            Detected  = $Detected
            Required  = $Required
            Notes     = $Notes
        }
    )
}

# ============================================================
# Function: Write-Section
# ============================================================

function Write-Section {

    param (
        [Parameter(Mandatory)]
        [string]$Title
    )

    Write-Host ""

    Write-Host `
        ("=" * 60) `
        -ForegroundColor DarkGray

    Write-Host `
        " $Title" `
        -ForegroundColor Cyan

    Write-Host `
        ("=" * 60) `
        -ForegroundColor DarkGray
}

# ============================================================
# Function: Convert-ToVersion
# ============================================================

function Convert-ToVersion {

    param (
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {

        return [version]$Value.ToString()
    }
    catch {

        return $null
    }
}

# ============================================================
# Function: Get-PackageFromExecutablePath
# ============================================================

function Get-PackageFromExecutablePath {

    param (
        [string]$ExecutablePath
    )

    if (-not $ExecutablePath) {
        return $null
    }

    $Pattern =
        "\\WindowsApps\\([^\\]+)_([0-9\.]+)_([^\\]+)__([^\\]+)"

    if ($ExecutablePath -match $Pattern) {

        return [PSCustomObject]@{
            PackageName    = $Matches[1]
            PackageVersion = $Matches[2]
            Architecture   = $Matches[3]
            PublisherId    = $Matches[4]
        }
    }

    return $null
}

# ============================================================
# Header
# ============================================================

Clear-Host

Write-Host ""

Write-Host `
    "Microsoft Teams SlimCore / AVD Endpoint Diagnostic v5" `
    -ForegroundColor Cyan

Write-Host "Computer : $env:COMPUTERNAME"

Write-Host "User     : $env:USERNAME"

Write-Host `
    "Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# ============================================================
# 1. Windows
# ============================================================

Write-Section "1. Windows"

$OS = Get-CimInstance `
    -ClassName Win32_OperatingSystem `
    -ErrorAction SilentlyContinue

if ($OS) {

    $BuildNumber = [int]$OS.BuildNumber

    if ($BuildNumber -ge $MinimumWindowsBuild) {

        $WindowsStatus = "PASS"
    }
    else {

        $WindowsStatus = "FAIL"
    }

    Add-Check `
        -Category "Operating System" `
        -Check "Windows version" `
        -Status $WindowsStatus `
        -Detected "$($OS.Caption) - Build $BuildNumber" `
        -Required "Windows 10 1809 / Build 17763 or later" `
        -Notes "SlimCore endpoint operating system check."

    Add-Check `
        -Category "Operating System" `
        -Check "Architecture" `
        -Status "INFO" `
        -Detected $OS.OSArchitecture `
        -Required "Supported Windows endpoint" `
        -Notes "Detected operating system architecture."
}
else {

    Add-Check `
        -Category "Operating System" `
        -Check "Windows detection" `
        -Status "FAIL" `
        -Detected "Unable to query operating system" `
        -Required "Windows endpoint" `
        -Notes "Win32_OperatingSystem query failed."
}

# ============================================================
# 2. Hardware
# ============================================================

Write-Section "2. Hardware"

$Computer = Get-CimInstance `
    -ClassName Win32_ComputerSystem `
    -ErrorAction SilentlyContinue

$MemoryBytes = [long]0

if (
    $null -ne $Computer -and
    $null -ne $Computer.TotalPhysicalMemory
) {

    try {

        $MemoryBytes =
            [long]$Computer.TotalPhysicalMemory
    }
    catch {

        $MemoryBytes =
            [long]0
    }
}

if ($MemoryBytes -gt 0) {

    $RAMValue =
        $MemoryBytes / 1GB

    $RAMGB =
        "{0:N1}" -f $RAMValue

    if ($RAMValue -ge $MinimumRAMGB) {

        $RAMStatus = "PASS"
    }
    else {

        $RAMStatus = "FAIL"
    }

    Add-Check `
        -Category "Hardware" `
        -Check "Physical memory" `
        -Status $RAMStatus `
        -Detected "$RAMGB GB" `
        -Required "$MinimumRAMGB GB minimum" `
        -Notes "Raw bytes: $MemoryBytes"
}
else {

    Add-Check `
        -Category "Hardware" `
        -Check "Physical memory" `
        -Status "WARN" `
        -Detected "Unable to determine" `
        -Required "$MinimumRAMGB GB minimum" `
        -Notes "TotalPhysicalMemory could not be retrieved."
}

$CPU = Get-CimInstance `
    -ClassName Win32_Processor `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($CPU) {

    $Cores =
        [int]$CPU.NumberOfCores

    if ($Cores -ge $MinimumCPUCores) {

        $CPUStatus = "PASS"
    }
    else {

        $CPUStatus = "FAIL"
    }

    Add-Check `
        -Category "Hardware" `
        -Check "CPU cores" `
        -Status $CPUStatus `
        -Detected "$($CPU.Name) - $Cores cores" `
        -Required "$MinimumCPUCores cores minimum" `
        -Notes "Physical CPU core count."
}

# ============================================================
# 3. AppX Package Inventory
# ============================================================

Write-Section "3. AVD and Windows 365 Client Packages"

$AllAppx = @(
    Get-AppxPackage `
        -AllUsers `
        -ErrorAction SilentlyContinue
)

$ClientPackageNames = @(
    "MicrosoftCorporationII.Windows365",
    "MicrosoftCorporationII.WindowsApp"
)

$ClientPackages = @(
    $AllAppx |
        Where-Object {
            $_.Name -in $ClientPackageNames
        } |
        Sort-Object `
            Name,
            Version `
            -Unique
)

if ($ClientPackages.Count -gt 0) {

    foreach ($App in $ClientPackages) {

        $PackageVersion =
            Convert-ToVersion `
                -Value $App.Version

        if (
            $PackageVersion -and
            $PackageVersion -ge
            $MinimumClientPackageVersion
        ) {

            $ClientStatus =
                "PASS"
        }
        else {

            $ClientStatus =
                "WARN"
        }

        Add-Check `
            -Category "AVD Client" `
            -Check "Windows App / Windows 365 package" `
            -Status $ClientStatus `
            -Detected "$($App.Name) - $($App.Version)" `
            -Required "$MinimumClientPackageVersion or later" `
            -Notes "Detected Windows App / Windows 365 client package."
    }
}
else {

    Add-Check `
        -Category "AVD Client" `
        -Check "Windows App / Windows 365 package" `
        -Status "WARN" `
        -Detected "Not detected" `
        -Required "$MinimumClientPackageVersion or later" `
        -Notes "No expected Windows App / Windows 365 client package was identified."
}

$HostPackages = @(
    $AllAppx |
        Where-Object {
            $_.Name -eq
            "MicrosoftCorporationII.AzureVirtualDesktopHostApp"
        }
)

foreach ($App in $HostPackages) {

    Add-Check `
        -Category "AVD Client" `
        -Check "Azure Virtual Desktop Host App" `
        -Status "INFO" `
        -Detected "$($App.Name) - $($App.Version)" `
        -Required "Informational only" `
        -Notes "This package is not compared with the Windows App minimum."
}

# ============================================================
# 4. Active AVD Client
# ============================================================

Write-Section "4. Active AVD Client"

$AVDProcesses = @(
    Get-Process `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProcessName -match
            "^(msrdc|msrdcw|WindowsApp)$"
        }
)

if ($AVDProcesses.Count -eq 0) {

    Add-Check `
        -Category "AVD Client" `
        -Check "Active client process" `
        -Status "WARN" `
        -Detected "Not detected" `
        -Required "Active AVD connection" `
        -Notes "Run the diagnostic while connected to AVD."
}

foreach ($Process in $AVDProcesses) {

    $ExecutablePath =
        $null

    $ExecutableVersion =
        $null

    $ActivePackage =
        $null

    try {

        $ExecutablePath =
            $Process.Path

        if ($ExecutablePath) {

            $ExecutableItem =
                Get-Item `
                    -Path $ExecutablePath `
                    -ErrorAction SilentlyContinue

            if ($ExecutableItem) {

                $ExecutableVersion =
                    $ExecutableItem.VersionInfo.FileVersion
            }

            $ActivePackage =
                Get-PackageFromExecutablePath `
                    -ExecutablePath $ExecutablePath
        }
    }
    catch {
    }

    if ($ActivePackage) {

        $PackageText =
            "$($ActivePackage.PackageName) $($ActivePackage.PackageVersion)"
    }
    else {

        $PackageText =
            "Not derived from executable path"
    }

    Add-Check `
        -Category "AVD Client" `
        -Check "Active client process" `
        -Status "PASS" `
        -Detected "$($Process.ProcessName) PID $($Process.Id), file $ExecutableVersion, package $PackageText, path $ExecutablePath" `
        -Required "Active supported AVD client" `
        -Notes "Executable currently servicing the connection."
}

# ============================================================
# 5. Visual C++ Runtime
# ============================================================

Write-Section "5. Visual C++ Runtime"

$VCRegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$VCRedists = @(
    Get-ItemProperty `
        -Path $VCRegistryPaths `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -like
            "*Microsoft Visual C++*Redistributable*"
        } |
        Sort-Object `
            DisplayName,
            DisplayVersion `
            -Unique
)

if ($VCRedists.Count -eq 0) {

    Add-Check `
        -Category "Runtime" `
        -Check "Visual C++ Redistributable" `
        -Status "FAIL" `
        -Detected "Not detected" `
        -Required "Visual C++ Redistributable" `
        -Notes "No matching Visual C++ Redistributable was found."
}
else {

    foreach ($VC in $VCRedists) {

        Add-Check `
            -Category "Runtime" `
            -Check "Visual C++ Redistributable" `
            -Status "PASS" `
            -Detected "$($VC.DisplayName) - $($VC.DisplayVersion)" `
            -Required "Visual C++ Redistributable" `
            -Notes "Runtime detected."
    }
}

# ============================================================
# 6. Teams AVD Plugin
# ============================================================

Write-Section "6. Teams AVD Plugin"

$PluginSearchRoots = @(
    "$env:ProgramFiles\Remote Desktop",
    "$env:ProgramFiles\WindowsApps",
    "${env:ProgramFiles(x86)}\Remote Desktop"
) |
    Where-Object {
        $_ -and
        (Test-Path $_)
    }

$PluginFiles = @()

foreach ($Root in $PluginSearchRoots) {

    $PluginFiles +=
        Get-ChildItem `
            -Path $Root `
            -Filter "MsTeamsPluginAvd.dll" `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue
}

$PluginFiles = @(
    $PluginFiles |
        Sort-Object FullName -Unique
)

if ($PluginFiles.Count -eq 0) {

    Add-Check `
        -Category "AVD Plugin" `
        -Check "MsTeamsPluginAvd.dll present" `
        -Status "FAIL" `
        -Detected "Not found" `
        -Required "Required" `
        -Notes "Teams AVD plugin was not found."
}
else {

    foreach ($Plugin in $PluginFiles) {

        Add-Check `
            -Category "AVD Plugin" `
            -Check "MsTeamsPluginAvd.dll present" `
            -Status "PASS" `
            -Detected "$($Plugin.VersionInfo.FileVersion) - $($Plugin.FullName)" `
            -Required "Required" `
            -Notes "Teams AVD plugin file detected."
    }
}

# ============================================================
# 7. Teams AVD Plugin Loaded State
# ============================================================

Write-Section "7. Teams AVD Plugin Loaded State"

$LoadedPlugins = @()

foreach ($Process in $AVDProcesses) {

    try {

        $LoadedModules = @(
            $Process.Modules |
                Where-Object {
                    $_.ModuleName -ieq
                    "MsTeamsPluginAvd.dll"
                }
        )

        foreach ($Module in $LoadedModules) {

            $PluginVersion = $null

            try {

                $PluginVersion = (
                    Get-Item `
                        -Path $Module.FileName `
                        -ErrorAction SilentlyContinue
                ).VersionInfo.FileVersion
            }
            catch {
            }

            $LoadedPlugins +=
                [PSCustomObject]@{
                    Process = $Process.ProcessName
                    PID     = $Process.Id
                    Path    = $Module.FileName
                    Version = $PluginVersion
                }
        }
    }
    catch {
    }
}

if ($LoadedPlugins.Count -gt 0) {

    foreach ($LoadedPlugin in $LoadedPlugins) {

        Add-Check `
            -Category "AVD Plugin" `
            -Check "MsTeamsPluginAvd.dll loaded" `
            -Status "PASS" `
            -Detected "$($LoadedPlugin.Process) PID $($LoadedPlugin.PID), version $($LoadedPlugin.Version), path $($LoadedPlugin.Path)" `
            -Required "Plugin loaded" `
            -Notes "Plugin is loaded into the active AVD client."
    }
}
elseif ($AVDProcesses.Count -gt 0) {

    Add-Check `
        -Category "AVD Plugin" `
        -Check "MsTeamsPluginAvd.dll loaded" `
        -Status "WARN" `
        -Detected "Not observed" `
        -Required "Plugin loaded" `
        -Notes "Module enumeration may require an elevated PowerShell session."
}
else {

    Add-Check `
        -Category "AVD Plugin" `
        -Check "MsTeamsPluginAvd.dll loaded" `
        -Status "INFO" `
        -Detected "Not tested" `
        -Required "Active AVD client" `
        -Notes "No active AVD client process was detected."
}

# ============================================================
# 8. SlimCore Packages
# ============================================================

Write-Section "8. SlimCore Packages"

$SlimCorePackages = @(
    $AllAppx |
        Where-Object {
            $_.Name -match
            "^Microsoft\.Teams\.SlimCoreVdi"
        } |
        Sort-Object `
            Name,
            Version
)

if ($SlimCorePackages.Count -eq 0) {

    Add-Check `
        -Category "SlimCore" `
        -Check "SlimCore packages" `
        -Status "WARN" `
        -Detected "Not detected" `
        -Required "SlimCore packages available" `
        -Notes "No SlimCore VDI packages were detected."
}
else {

    foreach ($Package in $SlimCorePackages) {

        if (
            $Package.Name -match
            "SlimCoreVdiHost"
        ) {

            $PackageType =
                "Host"
        }
        elseif (
            $Package.Name -match
            "SlimCoreVdiFwk"
        ) {

            $PackageType =
                "Framework"
        }
        else {

            $PackageType =
                "Other"
        }

        Add-Check `
            -Category "SlimCore" `
            -Check "SlimCore $PackageType package" `
            -Status "PASS" `
            -Detected "$($Package.Name) - $($Package.Version)" `
            -Required "Registered SlimCore package" `
            -Notes "Package status: $($Package.Status)"
    }
}

$SlimCorePackagesPath = Join-Path `
    -Path $ReportFolder `
    -ChildPath "SlimCore-Packages.csv"

$SlimCorePackages |
    Select-Object `
        Name,
        Version,
        PackageFullName,
        PackageFamilyName,
        InstallLocation,
        Status,
        Architecture |
    Export-Csv `
        -Path $SlimCorePackagesPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# 9. Current SlimCore Combination
# ============================================================

Write-Section "9. Current SlimCore Combination"

$CurrentSlimCoreHost = @(
    $SlimCorePackages |
        Where-Object {
            $_.Name -match
            "SlimCoreVdiHost"
        } |
        Sort-Object Version -Descending |
        Select-Object -First 1
)

$CurrentSlimCoreFramework = @(
    $SlimCorePackages |
        Where-Object {
            $_.Name -match
            "SlimCoreVdiFwk"
        } |
        Sort-Object Version -Descending |
        Select-Object -First 1
)

if ($CurrentSlimCoreHost.Count -gt 0) {

    Add-Check `
        -Category "SlimCore" `
        -Check "Current SlimCore Host" `
        -Status "PASS" `
        -Detected "$($CurrentSlimCoreHost[0].Name) - $($CurrentSlimCoreHost[0].Version)" `
        -Required "Current SlimCore Host" `
        -Notes "Highest detected SlimCore Host version."
}
else {

    Add-Check `
        -Category "SlimCore" `
        -Check "Current SlimCore Host" `
        -Status "WARN" `
        -Detected "Not detected" `
        -Required "SlimCore Host package" `
        -Notes "No SlimCore Host package was detected."
}

if ($CurrentSlimCoreFramework.Count -gt 0) {

    Add-Check `
        -Category "SlimCore" `
        -Check "Current SlimCore Framework" `
        -Status "PASS" `
        -Detected "$($CurrentSlimCoreFramework[0].Name) - $($CurrentSlimCoreFramework[0].Version)" `
        -Required "Current SlimCore Framework" `
        -Notes "Highest detected SlimCore Framework version."
}
else {

    Add-Check `
        -Category "SlimCore" `
        -Check "Current SlimCore Framework" `
        -Status "WARN" `
        -Detected "Not detected" `
        -Required "SlimCore Framework package" `
        -Notes "No SlimCore Framework package was detected."
}

if (
    $CurrentSlimCoreHost.Count -gt 0 -and
    $CurrentSlimCoreFramework.Count -gt 0
) {

    $HostVersion =
        Convert-ToVersion `
            -Value $CurrentSlimCoreHost[0].Version

    $FrameworkVersion =
        Convert-ToVersion `
            -Value $CurrentSlimCoreFramework[0].Version

    if ($HostVersion -eq $FrameworkVersion) {

        $VersionMatchStatus =
            "PASS"
    }
    else {

        $VersionMatchStatus =
            "WARN"
    }

    Add-Check `
        -Category "SlimCore" `
        -Check "Host and Framework version match" `
        -Status $VersionMatchStatus `
        -Detected "Host $HostVersion, Framework $FrameworkVersion" `
        -Required "Matching Host / Framework" `
        -Notes "Current SlimCore package version comparison."
}

# ============================================================
# 10. AppX / MSIX Policies
# ============================================================

Write-Section "10. AppX and MSIX Policies"

$PolicyPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Appx"
)

$PolicyCount = 0

foreach ($PolicyPath in $PolicyPaths) {

    if (Test-Path $PolicyPath) {

        $Policy = Get-ItemProperty `
            -Path $PolicyPath `
            -ErrorAction SilentlyContinue

        foreach ($Property in $Policy.PSObject.Properties) {

            if ($Property.Name -match "^PS") {
                continue
            }

            $PolicyCount++

            $PolicyStatus =
                "INFO"

            if (
                $Property.Name -eq
                "BlockNonAdminUserInstall" -and
                [int]$Property.Value -eq 1
            ) {

                $PolicyStatus =
                    "WARN"
            }

            Add-Check `
                -Category "MSIX Policy" `
                -Check $Property.Name `
                -Status $PolicyStatus `
                -Detected ([string]$Property.Value) `
                -Required "Must not prevent SlimCore MSIX deployment" `
                -Notes "Source: $PolicyPath"
        }
    }
}

if ($PolicyCount -eq 0) {

    Add-Check `
        -Category "MSIX Policy" `
        -Check "Explicit AppX policies" `
        -Status "INFO" `
        -Detected "No configured values detected" `
        -Required "MSIX deployment permitted" `
        -Notes "No explicit AppX policy values were found."
}

# ============================================================
# 11. SlimCore AppX / MSIX Events
# ============================================================

Write-Section "11. SlimCore AppX / MSIX Events"

$StartTime =
    (Get-Date).AddHours(
        -$EventLookbackHours
    )

$AllAppxEvents = @()

try {

    $AllAppxEvents = @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName =
                    "Microsoft-Windows-AppXDeploymentServer/Operational"

                StartTime =
                    $StartTime
            } `
            -ErrorAction Stop
    )
}
catch {

    Add-Check `
        -Category "SlimCore MSIX" `
        -Check "AppX event log query" `
        -Status "WARN" `
        -Detected "Unable to query AppX event log" `
        -Required "AppX Operational log available" `
        -Notes $_.Exception.Message
}

$RawSlimCoreEvents = @(
    $AllAppxEvents |
        Where-Object {
            $_.Message -match
            "Microsoft\.Teams\.SlimCoreVdi"
        } |
        Sort-Object TimeCreated
)

# ============================================================
# Parse SlimCore AppX Events
# ============================================================

$ParsedSlimCoreEvents = @()

foreach ($Event in $RawSlimCoreEvents) {

    $PackageFullName =
        $null

    $PackageType =
        $null

    $PackageVersion =
        $null

    $HRESULT =
        $null

    $Operation =
        "Other"

    $Succeeded =
        $false

    $Failed =
        $false

    if (
        $Event.LevelDisplayName -match
        "Error|Critical"
    ) {

        $Failed =
            $true
    }

    # --------------------------------------------------------
    # Framework package
    # --------------------------------------------------------

    $FrameworkPattern =
        "(Microsoft\.Teams\.SlimCoreVdiFwk\.win-x64\.[0-9]+\.[0-9]+_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_x64__8wekyb3d8bbwe)"

    if (
        $Event.Message -match
        $FrameworkPattern
    ) {

        $PackageFullName =
            $Matches[1]

        $PackageType =
            "Framework"
    }

    # --------------------------------------------------------
    # Host package
    # --------------------------------------------------------

    $HostPattern =
        "(Microsoft\.Teams\.SlimCoreVdiHost\.win-x64_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_x64__8wekyb3d8bbwe)"

    if (
        -not $PackageFullName -and
        $Event.Message -match
        $HostPattern
    ) {

        $PackageFullName =
            $Matches[1]

        $PackageType =
            "Host"
    }

    # --------------------------------------------------------
    # Package version
    # --------------------------------------------------------

    if (
        $PackageFullName -and
        $PackageFullName -match
        "_([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)_"
    ) {

        $PackageVersion =
            $Matches[1]
    }

    # --------------------------------------------------------
    # HRESULT
    # --------------------------------------------------------

    if (
        $Event.Message -match
        "(0x[0-9A-Fa-f]{8})"
    ) {

        $HRESULT =
            $Matches[1].ToUpper()
    }

    # --------------------------------------------------------
    # Operation
    # --------------------------------------------------------

    if (
        $Event.Message -match
        "Deployment Stage operation"
    ) {

        $Operation =
            "Stage"
    }
    elseif (
        $Event.Message -match
        "Deployment Register operation"
    ) {

        $Operation =
            "Register"
    }
    elseif (
        $Event.Message -match
        "RegisterByPackageFullName"
    ) {

        $Operation =
            "Register"
    }

    # --------------------------------------------------------
    # Successful completion
    # --------------------------------------------------------

    if (
        $Event.Message -match
        "finished successfully"
    ) {

        $Succeeded =
            $true
    }

    # --------------------------------------------------------
    # Parsed event object
    # --------------------------------------------------------

    $ParsedSlimCoreEvents +=
        [PSCustomObject]@{
            TimeCreated     = $Event.TimeCreated
            EventId         = $Event.Id
            Level           = $Event.LevelDisplayName
            PackageType     = $PackageType
            PackageVersion  = $PackageVersion
            PackageFullName = $PackageFullName
            Operation       = $Operation
            HRESULT         = $HRESULT
            Failed          = $Failed
            Succeeded       = $Succeeded
            Message         = $Event.Message
        }
}

$SlimCoreEventsPath = Join-Path `
    -Path $ReportFolder `
    -ChildPath "SlimCore-AppX-Events.csv"

$ParsedSlimCoreEvents |
    Export-Csv `
        -Path $SlimCoreEventsPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# 12. SlimCore Deployment Incidents
# ============================================================

Write-Section "12. SlimCore Deployment Incidents"

$SlimCoreErrorEvents = @(
    $ParsedSlimCoreEvents |
        Where-Object {
            $_.Failed -eq $true
        }
)

$SlimCoreIncidents = @()

# ------------------------------------------------------------
# Group duplicate Windows AppX error events.
#
# Example:
#
# Event 404 + Event 712
# Same package
# Same timestamp
#
# becomes one SlimCore incident.
# ------------------------------------------------------------

$IncidentGroups =
    $SlimCoreErrorEvents |
    Group-Object {

        if ($_.PackageFullName) {

            $PackageKey =
                $_.PackageFullName
        }
        elseif ($_.PackageVersion) {

            $PackageKey =
                "$($_.PackageType)-$($_.PackageVersion)"
        }
        else {

            $PackageKey =
                "UnknownSlimCorePackage"
        }

        $TimestampKey =
            $_.TimeCreated.ToString(
                "yyyy-MM-dd HH:mm:ss"
            )

        "$PackageKey|$TimestampKey"
    }

foreach ($Group in $IncidentGroups) {

    $IncidentEvents = @(
        $Group.Group |
            Sort-Object TimeCreated
    )

    $FirstEvent =
        $IncidentEvents |
        Select-Object -First 1

    $PackageFullName =
        $null

    $PackageVersion =
        $null

    $PackageType =
        $null

    # --------------------------------------------------------
    # Get package information from the grouped events
    # --------------------------------------------------------

    foreach ($IncidentEvent in $IncidentEvents) {

        if (
            -not $PackageFullName -and
            $IncidentEvent.PackageFullName
        ) {

            $PackageFullName =
                $IncidentEvent.PackageFullName
        }

        if (
            -not $PackageVersion -and
            $IncidentEvent.PackageVersion
        ) {

            $PackageVersion =
                $IncidentEvent.PackageVersion
        }

        if (
            -not $PackageType -and
            $IncidentEvent.PackageType
        ) {

            $PackageType =
                $IncidentEvent.PackageType
        }
    }

    # --------------------------------------------------------
    # Collect unique HRESULT values
    # --------------------------------------------------------

    $HRESULTs = @(
        $IncidentEvents |
            Where-Object {
                $_.HRESULT
            } |
            Select-Object `
                -ExpandProperty HRESULT `
                -Unique
    )

    if ($HRESULTs.Count -gt 0) {

        $HRESULTText =
            $HRESULTs -join ", "
    }
    else {

        $HRESULTText =
            "No HRESULT extracted"
    }

    # --------------------------------------------------------
    # Collect Windows Event IDs
    # --------------------------------------------------------

    $EventIds = @(
        $IncidentEvents |
            Select-Object `
                -ExpandProperty EventId `
                -Unique
    )

    # --------------------------------------------------------
    # Build incident object
    # --------------------------------------------------------

    $SlimCoreIncidents +=
        [PSCustomObject]@{
            IncidentTime      = $FirstEvent.TimeCreated
            PackageType       = $PackageType
            PackageVersion    = $PackageVersion
            PackageFullName   = $PackageFullName
            HRESULT           = $HRESULTText
            EventIds          = $EventIds -join ", "
            WindowsEventCount = $IncidentEvents.Count
            RecoveryStatus    = "NotChecked"
            RecoveryTime      = $null
            RecoveryOperation = $null
        }
}

# ============================================================
# 13. SlimCore Deployment Recovery
# ============================================================

Write-Section "13. SlimCore Deployment Recovery"

$RecoveredIncidentCount = 0

$PartiallyRecoveredIncidentCount = 0

$UnresolvedIncidentCount = 0

foreach ($Incident in $SlimCoreIncidents) {

    $MatchingSuccessfulEvents = @()

    # --------------------------------------------------------
    # Search for later successful events relating to the
    # same SlimCore package.
    # --------------------------------------------------------

    foreach ($CandidateEvent in $ParsedSlimCoreEvents) {

        # Event must occur after the original failure.

        if (
            $CandidateEvent.TimeCreated -le
            $Incident.IncidentTime
        ) {

            continue
        }

        # Event must have explicitly completed successfully.

        if (
            $CandidateEvent.Succeeded -ne
            $true
        ) {

            continue
        }

        # Only Stage and Register events count toward recovery.

        if (
            $CandidateEvent.Operation -ne "Stage" -and
            $CandidateEvent.Operation -ne "Register"
        ) {

            continue
        }

        $SamePackage =
            $false

        # ----------------------------------------------------
        # Preferred match:
        # Full package identity
        # ----------------------------------------------------

        if (
            $Incident.PackageFullName -and
            $CandidateEvent.PackageFullName
        ) {

            if (
                $CandidateEvent.PackageFullName -eq
                $Incident.PackageFullName
            ) {

                $SamePackage =
                    $true
            }
        }

        # ----------------------------------------------------
        # Fallback match:
        # Package type + package version
        # ----------------------------------------------------

        if (
            -not $SamePackage -and
            $Incident.PackageVersion -and
            $CandidateEvent.PackageVersion
        ) {

            if (
                $CandidateEvent.PackageVersion -eq
                $Incident.PackageVersion
            ) {

                if (
                    $CandidateEvent.PackageType -eq
                    $Incident.PackageType
                ) {

                    $SamePackage =
                        $true
                }
            }
        }

        if (-not $SamePackage) {

            continue
        }

        $MatchingSuccessfulEvents +=
            $CandidateEvent
    }

    # --------------------------------------------------------
    # Successful Register events
    # --------------------------------------------------------

    $SuccessfulRegisters = @(
        $MatchingSuccessfulEvents |
            Where-Object {
                $_.Operation -eq "Register"
            } |
            Sort-Object TimeCreated
    )

    # --------------------------------------------------------
    # Successful Stage events
    # --------------------------------------------------------

    $SuccessfulStages = @(
        $MatchingSuccessfulEvents |
            Where-Object {
                $_.Operation -eq "Stage"
            } |
            Sort-Object TimeCreated
    )

    # --------------------------------------------------------
    # Fully recovered
    #
    # A later successful Register is the strongest indication
    # that the earlier deployment failure recovered.
    # --------------------------------------------------------

    if ($SuccessfulRegisters.Count -gt 0) {

        $RecoveryEvent =
            $SuccessfulRegisters[0]

        $Incident.RecoveryStatus =
            "Recovered"

        $Incident.RecoveryTime =
            $RecoveryEvent.TimeCreated

        $Incident.RecoveryOperation =
            "Register"

        $RecoveredIncidentCount++

        Add-Check `
            -Category "SlimCore MSIX" `
            -Check "Recovered SlimCore incident" `
            -Status "PASS" `
            -Detected "$($Incident.IncidentTime) $($Incident.HRESULT) recovered at $($RecoveryEvent.TimeCreated)" `
            -Required "Successful registration after failure" `
            -Notes "Package: $($Incident.PackageFullName). $($Incident.WindowsEventCount) Windows error events grouped into this incident."

        continue
    }

    # --------------------------------------------------------
    # Partially recovered
    #
    # Package successfully staged but no subsequent successful
    # registration was found.
    # --------------------------------------------------------

    if ($SuccessfulStages.Count -gt 0) {

        $RecoveryEvent =
            $SuccessfulStages[0]

        $Incident.RecoveryStatus =
            "PartiallyRecovered"

        $Incident.RecoveryTime =
            $RecoveryEvent.TimeCreated

        $Incident.RecoveryOperation =
            "Stage"

        $PartiallyRecoveredIncidentCount++

        Add-Check `
            -Category "SlimCore MSIX" `
            -Check "Partially recovered SlimCore incident" `
            -Status "WARN" `
            -Detected "$($Incident.IncidentTime) $($Incident.HRESULT), staged at $($RecoveryEvent.TimeCreated)" `
            -Required "Successful registration after staging" `
            -Notes "SlimCore staging succeeded, but a later successful Register event was not identified."

        continue
    }

    # --------------------------------------------------------
    # Unresolved
    # --------------------------------------------------------

    $Incident.RecoveryStatus =
        "Unresolved"

    $UnresolvedIncidentCount++

    Add-Check `
        -Category "SlimCore MSIX" `
        -Check "Unresolved SlimCore incident" `
        -Status "WARN" `
        -Detected "$($Incident.IncidentTime) $($Incident.HRESULT)" `
        -Required "Later successful Stage/Register event" `
        -Notes "Package: $($Incident.PackageFullName). No later successful deployment activity was identified."
}

# ============================================================
# Export SlimCore Incident Report
# ============================================================

$SlimCoreIncidentPath = Join-Path `
    -Path $ReportFolder `
    -ChildPath "SlimCore-AppX-Incidents.csv"

$SlimCoreIncidents |
    Export-Csv `
        -Path $SlimCoreIncidentPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# Overall Incident Status
# ============================================================

$IncidentCount =
    @($SlimCoreIncidents).Count

if ($IncidentCount -eq 0) {

    Add-Check `
        -Category "SlimCore MSIX" `
        -Check "SlimCore deployment incidents" `
        -Status "PASS" `
        -Detected "No incidents detected" `
        -Required "No unresolved failures" `
        -Notes "No SlimCore-specific deployment failures were detected."
}
elseif (
    $UnresolvedIncidentCount -eq 0 -and
    $PartiallyRecoveredIncidentCount -eq 0
) {

    Add-Check `
        -Category "SlimCore MSIX" `
        -Check "SlimCore deployment incidents" `
        -Status "PASS" `
        -Detected "$IncidentCount incident(s), all recovered" `
        -Required "No unresolved failures" `
                -Notes "$RecoveredIncidentCount incident(s) reached successful registration."
}
else {

    Add-Check `
        -Category "SlimCore MSIX" `
        -Check "SlimCore deployment incidents" `
        -Status "WARN" `
        -Detected "$IncidentCount incident(s), $UnresolvedIncidentCount unresolved, $PartiallyRecoveredIncidentCount partially recovered" `
        -Required "No unresolved failures" `
        -Notes "$RecoveredIncidentCount incident(s) fully recovered."
}

# ============================================================
# Latest Successful SlimCore Registration
# ============================================================

$LatestSuccessfulRegistration = @(
    $ParsedSlimCoreEvents |
        Where-Object {
            $_.Succeeded -eq $true -and
            $_.Operation -eq "Register"
        } |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 1
)

if ($LatestSuccessfulRegistration.Count -gt 0) {

    $LatestRegistration =
        $LatestSuccessfulRegistration[0]

    Add-Check `
        -Category "SlimCore MSIX" `
        -Check "Latest successful SlimCore registration" `
        -Status "PASS" `
        -Detected "$($LatestRegistration.TimeCreated) - $($LatestRegistration.PackageVersion)" `
        -Required "Successful SlimCore registration" `
        -Notes "Package: $($LatestRegistration.PackageFullName)"
}

# ============================================================
# Console Incident Analysis
# ============================================================

Write-Host ""

Write-Host `
    "SlimCore incident analysis:" `
    -ForegroundColor Cyan

Write-Host `
    "  Windows error events : $($SlimCoreErrorEvents.Count)"

Write-Host `
    "  Unique incidents     : $IncidentCount"

Write-Host `
    "  Fully recovered      : $RecoveredIncidentCount"

Write-Host `
    "  Partially recovered  : $PartiallyRecoveredIncidentCount"

Write-Host `
    "  Unresolved           : $UnresolvedIncidentCount"

Write-Host ""

# ============================================================
# 14. Media Privacy
# ============================================================

Write-Section "14. Media Privacy"

$MediaCapabilities = @(
    @{
        Name = "Microphone"
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    },
    @{
        Name = "Webcam"
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    }
)

foreach ($Capability in $MediaCapabilities) {

    $Consent = $null

    if (Test-Path $Capability.Path) {

        $Consent =
            Get-ItemPropertyValue `
                -Path $Capability.Path `
                -Name "Value" `
                -ErrorAction SilentlyContinue
    }

    if ($Consent -eq "Deny") {

        $PrivacyStatus =
            "FAIL"

        $PrivacyDetected =
            "Deny"
    }
    elseif ($Consent) {

        $PrivacyStatus =
            "PASS"

        $PrivacyDetected =
            $Consent
    }
    else {

        $PrivacyStatus =
            "INFO"

        $PrivacyDetected =
            "Unable to determine"
    }

    Add-Check `
        -Category "Media Privacy" `
        -Check "$($Capability.Name) access" `
        -Status $PrivacyStatus `
        -Detected $PrivacyDetected `
        -Required "Media access permitted" `
        -Notes "Current user privacy state."
}

# ============================================================
# 15. Display Results
# ============================================================

Write-Section "SlimCore Readiness Results"

foreach ($Result in $Results) {

    switch ($Result.Status) {

        "PASS" {
            $Colour = "Green"
        }

        "FAIL" {
            $Colour = "Red"
        }

        "WARN" {
            $Colour = "Yellow"
        }

        default {
            $Colour = "Cyan"
        }
    }

    Write-Host (
        "[{0,-4}] {1,-40} : {2}" -f `
            $Result.Status,
            $Result.Check,
            $Result.Detected
    ) -ForegroundColor $Colour
}

# ============================================================
# 16. Result Counts
# ============================================================

$PassCount = @(
    $Results |
        Where-Object {
            $_.Status -eq "PASS"
        }
).Count

$FailCount = @(
    $Results |
        Where-Object {
            $_.Status -eq "FAIL"
        }
).Count

$WarnCount = @(
    $Results |
        Where-Object {
            $_.Status -eq "WARN"
        }
).Count

$InfoCount = @(
    $Results |
        Where-Object {
            $_.Status -eq "INFO"
        }
).Count

# ============================================================
# 17. Overall Diagnostic Result
# ============================================================

if ($FailCount -gt 0) {

    $OverallResult =
        "One or more SlimCore prerequisite checks failed."

    $OverallColour =
        "Red"
}
elseif ($UnresolvedIncidentCount -gt 0) {

    $OverallResult =
        "Prerequisites passed, but unresolved SlimCore deployment incidents were detected."

    $OverallColour =
        "Yellow"
}
elseif ($PartiallyRecoveredIncidentCount -gt 0) {

    $OverallResult =
        "Prerequisites passed, but one or more SlimCore deployment incidents only partially recovered."

    $OverallColour =
        "Yellow"
}
elseif ($WarnCount -gt 0) {

    $OverallResult =
        "SlimCore prerequisites and MSIX deployment are healthy. Review non-MSIX warnings."

    $OverallColour =
        "Yellow"
}
else {

    $OverallResult =
        "SlimCore prerequisites passed and no unresolved deployment incidents were detected."

    $OverallColour =
        "Green"
}

# ============================================================
# 18. Console Summary
# ============================================================

Write-Section "Summary"

Write-Host `
    "PASS : $PassCount" `
    -ForegroundColor Green

Write-Host `
    "FAIL : $FailCount" `
    -ForegroundColor Red

Write-Host `
    "WARN : $WarnCount" `
    -ForegroundColor Yellow

Write-Host `
    "INFO : $InfoCount" `
    -ForegroundColor Cyan

Write-Host ""

Write-Host `
    "RESULT: $OverallResult" `
    -ForegroundColor $OverallColour

Write-Host ""

Write-Host `
    "SlimCore incident analysis:" `
    -ForegroundColor Cyan

Write-Host `
    "  SlimCore AppX events     : $($ParsedSlimCoreEvents.Count)"

Write-Host `
    "  Windows error events     : $($SlimCoreErrorEvents.Count)"

Write-Host `
    "  Unique incidents         : $IncidentCount"

Write-Host `
    "  Fully recovered          : $RecoveredIncidentCount"

Write-Host `
    "  Partially recovered      : $PartiallyRecoveredIncidentCount"

Write-Host `
    "  Unresolved incidents     : $UnresolvedIncidentCount"

# ============================================================
# 19. Export Results CSV
# ============================================================

$ResultsPath = Join-Path `
    -Path $ReportFolder `
    -ChildPath "SlimCore-Results.csv"

$Results |
    Export-Csv `
        -Path $ResultsPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# 20. Build Summary TXT
# ============================================================

$SummaryPath = Join-Path `
    -Path $ReportFolder `
    -ChildPath "SlimCore-Summary.txt"

$DetailedResultsText = (
    $Results |
        ForEach-Object {

            "[$($_.Status)] $($_.Category) | $($_.Check) | $($_.Detected) | $($_.Notes)"
        } |
        Out-String
)

$SummaryText = @"
Microsoft Teams SlimCore / AVD Endpoint Diagnostic v5

Computer:
$env:COMPUTERNAME

User:
$env:USERNAME

Date:
$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Event Lookback:
$EventLookbackHours hours

PASS:
$PassCount

FAIL:
$FailCount

WARN:
$WarnCount

INFO:
$InfoCount

SlimCore AppX Events:
$($ParsedSlimCoreEvents.Count)

Windows Error Events:
$($SlimCoreErrorEvents.Count)

Unique SlimCore Incidents:
$IncidentCount

Fully Recovered Incidents:
$RecoveredIncidentCount

Partially Recovered Incidents:
$PartiallyRecoveredIncidentCount

Unresolved Incidents:
$UnresolvedIncidentCount

Overall Result:
$OverallResult

============================================================
Detailed Results
============================================================

$DetailedResultsText
"@

$SummaryText |
    Out-File `
        -FilePath $SummaryPath `
        -Encoding UTF8

# ============================================================
# 21. Diagnostic Bundle
# ============================================================

Write-Section "Diagnostic Bundle"

Write-Host `
    "Report folder:" `
    -ForegroundColor Cyan

Write-Host $ReportFolder

Write-Host ""

Write-Host `
    "Generated files:" `
    -ForegroundColor Cyan

Write-Host "  SlimCore-Summary.txt"
Write-Host "  SlimCore-Results.csv"
Write-Host "  SlimCore-Packages.csv"
Write-Host "  SlimCore-AppX-Events.csv"
Write-Host "  SlimCore-AppX-Incidents.csv"

Write-Host ""

Write-Host `
    "Diagnostic completed." `
    -ForegroundColor Cyan

Write-Host ""