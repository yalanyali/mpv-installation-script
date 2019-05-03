@echo OFF
pushd %~dp0
@PowerShell.exe -ExecutionPolicy bypass -Command "Invoke-Expression -Command ((Get-Content -Path '%~f0' | Select-Object -Skip 4) -join [environment]::NewLine)"
@exit /b %Errorlevel%

# PS Script below

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

function Check-7z {
    $7zdir = (Get-Location).Path + "\7z"
    if (-not (Test-Path ($7zdir + "\7za.exe")))
    {
        $download_file = (Get-Location).Path + "\7z.zip"
        Write-Host "Downloading 7z" -ForegroundColor Green
        Invoke-WebRequest -Uri "http://download.sourceforge.net/sevenzip/7za920.zip" -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox -OutFile $download_file
        Write-Host "Extracting 7z" -ForegroundColor Green
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($download_file, $7zdir)
        Remove-Item -Force $download_file
    }
    else
    {
        Write-Host "7z already exist. Skipped download" -ForegroundColor Green
    }
}

function Check-PowershellVersion {
    $version = $PSVersionTable.PSVersion.Major
    Write-Host "Checking Windows PowerShell version -- $version" -ForegroundColor Green
    if ($version -le 2)
    {
        Write-Host "Using Windows PowerShell $version is unsupported. Upgrade your Windows PowerShell." -ForegroundColor Red
        throw
    }
}

function Check-Youtubedl {
    $youtubedl = (Get-Location).Path + "\youtube-dl.exe"
    $is_exist = Test-Path $youtubedl
    if (-not $is_exist) {
        Write-Host "youtube-dl doesn't exist" -ForegroundColor Cyan
    }
    return $is_exist
}

function Check-Mpv {
    $mpv = (Get-Location).Path + "\mpv.exe"
    $is_exist = Test-Path $mpv
    if (-not $is_exist) {
        Write-Host "mpv doesn't exist" -ForegroundColor Cyan
    }
    return $is_exist
}

function Check-Scripts {
    $scripts = (Get-Location).Path + "\scripts"
    $is_exist = Test-Path $scripts
    if (-not $is_exist) {
        Write-Host "scripts folder doesn't exist" -ForegroundColor Cyan
    }
    return $is_exist
}

function Check-Config {
    $scripts = (Get-Location).Path + "\mpv"
    $is_exist = Test-Path $scripts
    if (-not $is_exist) {
        Write-Host "config folder doesn't exist" -ForegroundColor Cyan
    }
    return $is_exist
}

function Download-Mpv ($filename) {
    Write-Host "Downloading" $filename -ForegroundColor Green
    $link = "http://download.sourceforge.net/mpv-player-windows/" + $filename
    Invoke-WebRequest -Uri $link -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox -OutFile $filename
}

function Download-Youtubedl ($version) {
    Write-Host "Downloading youtube-dl ($version)" -ForegroundColor Green
    $link = "https://github.com/rg3/youtube-dl/releases/download/" + $version + "/youtube-dl.exe"
    Invoke-WebRequest -Uri $link -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox -OutFile "youtube-dl.exe"
}

function Download-Scripts ($version) {
    Write-Host "Downloading mpv-scripts ($version)" -ForegroundColor Green
    $link = "https://github.com/yalanyali/mpv-scripts/releases/download/" + $version + "/mpv-scripts.zip"
    Invoke-WebRequest -Uri $link -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox -OutFile "mpv-scripts.zip"
}

function Download-Config ($version) {
    Write-Host "Downloading mpv-config ($version)" -ForegroundColor Green
    $link = "https://github.com/yalanyali/mpv-config/releases/download/" + $version + "/mpv-config.zip"
    Invoke-WebRequest -Uri $link -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox -OutFile "mpv-config.zip"
}

function Extract-Archive ($file) {
    Check-7z
    $7za = (Get-Location).Path + "\7z\7za.exe"
    Write-Host "Extracting" $file -ForegroundColor Green
    & $7za x -y $file
    Remove-Item -Force $file
}

function Get-Latest-Mpv($Arch) {
    $i686_link = "https://sourceforge.net/projects/mpv-player-windows/rss?path=/32bit"
    $x86_64_link = "https://sourceforge.net/projects/mpv-player-windows/rss?path=/64bit"
    $link = ''
    switch ($Arch)
    {
        i686 { $link = $i686_link}
        x86_64 { $link = $x86_64_link }
    }
    Write-Host "Fetching RSS feed for mpv" -ForegroundColor Green
    $result = [xml](New-Object System.Net.WebClient).DownloadString($link)
    $latest = $result.rss.channel.item.link[0]
    $filename = $latest.split("/")[-2]
    return [System.Uri]::UnescapeDataString($filename)
}

function Get-Latest-Youtubedl {
    $link = "https://github.com/rg3/youtube-dl/releases.atom"
    Write-Host "Fetching RSS feed for youtube-dl" -ForegroundColor Green
    $result = [xml](New-Object System.Net.WebClient).DownloadString($link)
    $version = $result.feed.entry[0].title.split(" ")[-1]
    return $version
}

function Get-Latest-Scripts {
    $link = "https://github.com/yalanyali/mpv-scripts/releases.atom"
    Write-Host "Fetching RSS feed for mpv-scripts" -ForegroundColor Green
    $result = [xml](New-Object System.Net.WebClient).DownloadString($link)
    $version = $result.feed.entry[0].title.split(" ")[-1]
    return $version
}

function Get-Latest-Config {
    $link = "https://github.com/yalanyali/mpv-config/releases.atom"
    Write-Host "Fetching RSS feed for mpv-config" -ForegroundColor Green
    $result = [xml](New-Object System.Net.WebClient).DownloadString($link)
    $version = $result.feed.entry[0].title.split(" ")[-1]
    return $version
}

function Get-Arch {
    # Reference: http://superuser.com/a/891443
    $FilePath = [System.IO.Path]::Combine((Get-Location).Path, 'mpv.exe')
    [int32]$MACHINE_OFFSET = 4
    [int32]$PE_POINTER_OFFSET = 60

    [byte[]]$data = New-Object -TypeName System.Byte[] -ArgumentList 4096
    $stream = New-Object -TypeName System.IO.FileStream -ArgumentList ($FilePath, 'Open', 'Read')
    $stream.Read($data, 0, 4096) | Out-Null

    # DOS header is 64 bytes, last element, long (4 bytes) is the address of the PE header
    [int32]$PE_HEADER_ADDR = [System.BitConverter]::ToInt32($data, $PE_POINTER_OFFSET)
    [int32]$machineUint = [System.BitConverter]::ToUInt16($data, $PE_HEADER_ADDR + $MACHINE_OFFSET)

    $result = "" | select FilePath, FileType
    $result.FilePath = $FilePath

    switch ($machineUint)
    {
        0      { $result.FileType = 'Native' }
        0x014c { $result.FileType = 'i686' } # 32bit
        0x0200 { $result.FileType = 'Itanium' }
        0x8664 { $result.FileType = 'x86_64' } # 64bit
    }

    $result
}

function ExtractGitFromFile {
    $stripped = .\mpv --no-config | select-string "mpv" | select-object -First 1
    # mpv 0.27.0-3-g2f41b834b3 (C) 20...
    $pattern = "-g([a-z0-9-]{7})"
    $bool = $stripped -match $pattern
    return $matches[1] # 2f41b83
}

function ExtractGitFromURL($filename) {
    # mpv-x86_64-20170916-git-2f41b83.7z
    $pattern = "-git-([a-z0-9-]{7})"
    $bool = $filename -match $pattern
    return $matches[1] # git-2f41b83
}

function Test-Admin
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Upgrade-Mpv {
    $need_download = $false
    $remoteName = ""
    $arch = ""

    if (Check-Mpv) {
        $arch = (Get-Arch).FileType
        $remoteName = Get-Latest-Mpv $arch
        if ((ExtractGitFromFile) -match (ExtractGitFromURL $remoteName))
        {
            Write-Host "You are already using the latest mpv build -- $remoteName" -ForegroundColor Green
            $need_download = $false
        }
        else {
            Write-Host "A newer mpv build is available" -ForegroundColor Green
            $need_download = $true
        }
    }
    else {
        $need_download = $true
        if (Test-Path (Join-Path $env:windir "SysWow64")) {
            Write-Host "Detected system type is 64-bit" -ForegroundColor Green
            $arch = "x86_64"
        }
        else {
            Write-Host "Detected system type is 32-bit" -ForegroundColor Green
            $arch = "i686"
        }
        $remoteName = Get-Latest-Mpv $arch
    }

    if ($need_download) {
        Download-Mpv $remoteName
        $global:mpvInstalled = $true
        Extract-Archive $remoteName
        New-Item -ItemType Directory -Force -Path tools
        Move-Item -Force installer/mpv-install.bat tools/mpv-register-types.bat
        Move-Item -Force installer/mpv-uninstall.bat tools/mpv-unregister-types.bat
        Move-Item -Force installer/mpv-icon.ico tools/mpv-icon.ico
        Remove-Item -Force -R installer
        Remove-Item -Force updater.bat
    }
}

function Upgrade-Youtubedl {
    $need_download = $false
    $latest_release = Get-Latest-Youtubedl

    if (Check-Youtubedl) {
        if ((.\youtube-dl --version) -match ($latest_release)) {
            Write-Host "You are already using latest youtube-dl -- $latest_release" -ForegroundColor Green
            $need_download = $false
        }
        else {
            Write-Host "Newer youtube-dl build available" -ForegroundColor Green
            $need_download = $true
        }
    }
    else {
        $need_download = $true
    }

    if ($need_download) {
        Download-Youtubedl $latest_release
    }
}

function Upgrade-Scripts {
    $need_download = $false
    $latest_release = Get-Latest-Scripts

    if (Check-Scripts) {
        if ((Get-Content scripts/version) -match ($latest_release)) {
            Write-Host "You are already using latest mpv-scripts -- $latest_release" -ForegroundColor Green
            $need_download = $false
        }
        else {
            Write-Host "Newer mpv-scripts build available -- $latest_release" -ForegroundColor Green
            $need_download = $true
        }
    }
    else {
        $need_download = $true
    }

    if ($need_download) {
        Download-Scripts $latest_release
        Extract-Archive "mpv-scripts.zip"
    }
}

function Upgrade-Config {
    $need_download = $false
    $latest_release = Get-Latest-Config

    if (Check-Config) {
        if ((Get-Content mpv/version) -match ($latest_release)) {
            Write-Host "You are already using latest mpv-config -- $latest_release" -ForegroundColor Green
            $need_download = $false
        }
        else {
            Write-Host "Newer mpv-config build available -- $latest_release" -ForegroundColor Green
            $need_download = $true
        }
    }
    else {
        $need_download = $true
    }

    if ($need_download) {
        Download-Config $latest_release
        Extract-Archive "mpv-config.zip"
    }
}

#
# Main script entry point
#
if (Test-Admin) {
    Write-Host "Running script with administrator privileges" -ForegroundColor Yellow
}
else {
    Write-Host "Running script without administrator privileges`nPress ENTER to continue..." -ForegroundColor Red
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    cls
}

$global:mpvInstalled = $false

try {
    Check-PowershellVersion
    Upgrade-Mpv
    Upgrade-Config
    Upgrade-Scripts
    Upgrade-Youtubedl
    if (Test-Path 7z) {
        Remove-Item -Force -R 7z
    }
    if (!$mpvInstalled) {
        Write-Host "Press ENTER to register media file extensions with mpv." -ForegroundColor Red
        $k = [System.Console]::ReadKey($true).Key.ToString()
        if ($k -eq "Enter") {
            Start-Process "cmd.exe" "/c .\tools\mpv-register-types.bat"
        }
    }
    Write-Host "Operation completed" -ForegroundColor Magenta
    Write-Host "Press any key to exit..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
catch [System.Exception] {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
