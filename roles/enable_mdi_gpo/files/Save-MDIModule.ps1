#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Pre-stages the DefenderForIdentity PowerShell module for offline lab deployment.

.DESCRIPTION
    Run this script ONCE on any machine WITH internet access before deploying the lab.
    It downloads the DefenderForIdentity module from PSGallery and saves it next to
    this script as a DefenderForIdentity/ directory.

    The enable_mdi_gpo Ansible role automatically detects that directory during
    deployment and installs the module on the DC without requiring internet access.

.EXAMPLE
    # On your laptop or any internet-connected machine:
    cd roles/enable_mdi_gpo/files/
    .\Save-MDIModule.ps1

    # Then deploy as normal — no internet needed on the DC:
    ludus range deploy

.NOTES
    If you prefer to install from PSGallery at deploy time (DC has internet),
    simply do not run this script. The role falls back to PSGallery automatically.
#>

$ErrorActionPreference = 'Stop'
$OutPath = $PSScriptRoot

Write-Host "Staging DefenderForIdentity module..."
Write-Host "Destination : $OutPath"
Write-Host "Source      : PSGallery (internet required for this step only)"
Write-Host ""

# Trust PSGallery to avoid interactive prompts
if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

# Ensure NuGet provider is available (required by Save-Module)
$nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
    Write-Host "Installing NuGet provider..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false | Out-Null
}

Write-Host "Downloading DefenderForIdentity from PSGallery..."
Save-Module -Name DefenderForIdentity -Path $OutPath -Force

$moduleDir = Join-Path $OutPath 'DefenderForIdentity'
if (Test-Path $moduleDir) {
    $version = (Get-ChildItem $moduleDir -Directory | Select-Object -First 1).Name
    Write-Host ""
    Write-Host "SUCCESS"
    Write-Host "  Module  : DefenderForIdentity $version"
    Write-Host "  Path    : $moduleDir"
    Write-Host ""
    Write-Host "The enable_mdi_gpo role will copy this directory to the DC"
    Write-Host "automatically during deployment. No further action needed."
} else {
    throw "Save-Module completed but '$moduleDir' was not created. Check PSGallery connectivity."
}
