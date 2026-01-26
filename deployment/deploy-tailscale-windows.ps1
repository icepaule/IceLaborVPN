#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tailscale Deployment Script for Headscale (Windows)
    For ManageEngine Endpoint Central
.DESCRIPTION
    - Installs Tailscale if not present
    - Retrieves dynamic authkey via Headscale API
    - Connects to Headscale server
.NOTES
    Part of IceLaborVPN - https://github.com/icepaule/IceLaborVPN
#>

$ErrorActionPreference = "Stop"

# === CONFIGURATION - MODIFY THESE VALUES ===
$HEADSCALE_URL = "https://headscale.example.com"           # Your Headscale URL
$HEADSCALE_API_KEY = "YOUR_HEADSCALE_API_KEY_HERE"         # Generate with: headscale apikeys create --expiration 365d
$HEADSCALE_USER = "default"                                 # Headscale user/namespace
$TAILSCALE_MSI_URL = "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi"
# ============================================

$LOG_FILE = "$env:TEMP\tailscale-deploy.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path $LOG_FILE -Value $logMessage
}

function Get-AuthKey {
    Write-Log "Retrieving authkey from Headscale API..."
    
    $headers = @{
        "Authorization" = "Bearer $HEADSCALE_API_KEY"
        "Content-Type" = "application/json"
    }
    
    $body = @{
        user = $HEADSCALE_USER
        reusable = $false
        ephemeral = $false
        expiration = (Get-Date).AddHours(1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    } | ConvertTo-Json
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri "$HEADSCALE_URL/api/v1/preauthkey" -Method Post -Headers $headers -Body $body
        $authKey = $response.preAuthKey.key
        Write-Log "Authkey received: $($authKey.Substring(0,8))..."
        return $authKey
    }
    catch {
        Write-Log "ERROR retrieving authkey: $_"
        throw
    }
}

function Install-Tailscale {
    $tailscalePath = "C:\Program Files\Tailscale\tailscale.exe"
    
    if (Test-Path $tailscalePath) {
        Write-Log "Tailscale already installed"
        return
    }
    
    Write-Log "Installing Tailscale..."
    $msiPath = "$env:TEMP\tailscale-setup.msi"
    
    Write-Log "Downloading from $TAILSCALE_MSI_URL..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $TAILSCALE_MSI_URL -OutFile $msiPath -UseBasicParsing
    
    Write-Log "Running MSI installation..."
    $process = Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /quiet /norestart" -Wait -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Log "ERROR: MSI installation failed (Exit Code: $($process.ExitCode))"
        throw "Installation failed"
    }
    
    Write-Log "Waiting for Tailscale service..."
    Start-Sleep -Seconds 5
    Set-Service -Name "Tailscale" -StartupType Automatic
    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
    
    Write-Log "Tailscale installed successfully"
}

function Connect-Tailscale {
    param([string]$AuthKey)
    
    $tailscale = "C:\Program Files\Tailscale\tailscale.exe"
    $hostname = $env:COMPUTERNAME.ToLower()
    
    Write-Log "Connecting to Headscale as '$hostname'..."
    
    # Set registry for custom login URL
    $regPath = "HKLM:\SOFTWARE\Tailscale IPN"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "UnattendedMode" -Value "always" -Type String
    Set-ItemProperty -Path $regPath -Name "LoginURL" -Value $HEADSCALE_URL -Type String
    
    $args = "up --login-server=$HEADSCALE_URL --authkey=$AuthKey --hostname=$hostname --force-reauth"
    $process = Start-Process -FilePath $tailscale -ArgumentList $args -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -ne 0) {
        Write-Log "WARNING: tailscale up exit code: $($process.ExitCode)"
    }
    
    Start-Sleep -Seconds 3
    $status = & $tailscale status 2>&1
    Write-Log "Tailscale Status: $status"
}

# === MAIN ===
try {
    Write-Log "=== Tailscale Deployment Start ==="
    Write-Log "Computer: $env:COMPUTERNAME"
    
    Install-Tailscale
    $authKey = Get-AuthKey
    Connect-Tailscale -AuthKey $authKey
    
    Write-Log "=== Deployment completed successfully ==="
    exit 0
}
catch {
    Write-Log "=== DEPLOYMENT FAILED: $_ ==="
    exit 1
}
