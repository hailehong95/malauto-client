# require: powershell4 or over
# support on: Windows 8, 8.1, 10, Windows Server 2012, 2016, 2019

function InitDirectory {
    if (!(Test-Path .\reports)) {
        New-Item -ItemType Directory -Force -Path .\reports
    }

    if (!(Test-Path .\upload)) {
        New-Item -ItemType Directory -Force -Path .\upload
    }
}

function CheckBinarys {
    if(!(Test-Path .\bin\autorunsc.exe) -or !(Test-Path .\bin\BrowserAddonsView.exe) -or !(Test-Path .\bin\lastactivityview.exe) -or !(Test-Path .\bin\psloglist.exe) -or !(Test-Path .\bin\sigcheck.exe) -or !(Test-Path .\bin\7z\7za.exe)) {
        CleaningData;
        exit
    }
}

function Get-MessageBox {
    param ( $Message='', $Title='', $Type='')
    # Type: Asterisk, Warning, Error, None, Stop,..
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    [System.Windows.MessageBox]::Show($Message, $Title, 'OKCancel', $Type) | Out-Null
}

function Write-Logs {
    param ( $LogFile='', $Message='')
    $text = "{0} {1}" -f (Get-Date).ToString("HH:mm:ss dd-MM-yyyy"), $Message
    Add-Content -Path $LogFile -Value $text
}

function Get-FileNameReport {
    param ( $FullName='', $EmployeeID='' )
    try {
        $rdm_string = -join ((48..57) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        $name_generated = "{0}_{1}_{2}" -f $EmployeeID, $FullName, $rdm_string
    }
    catch {
        return $rdm_string
    }
    return $name_generated
}

<#
# Ref: https://github.com/davehull/Kansa/blob/master/Modules/ASEP/Get-Autorunsc.ps1
# Run: Get-AutorunscJson | ConvertTo-Json | Out-File -FilePath .\reports\autorun.json
#>
function Get-AutorunscJson {
    if (Test-Path ".\bin\autorunsc.exe") {
        & .\bin\autorunsc.exe /accepteula -a * -c -h -s -m '*' -nobanner 2> $null | ConvertFrom-Csv | ForEach-Object { $_ }
    }
}

<#
# Returns output from the SysInternals' sicheck.exe utility
# Ref: https://github.com/davehull/Kansa/blob/master/Modules/ASEP/Get-Sigcheck.ps1
# Get-FilesSigCkJson | ConvertTo-Json | Out-File -FilePath .\reports\files.json
#>
function Get-FilesSigCkJson {
    $WinTempDir = $env:windir + "\Temp"
    $WinDebugDir = $env:windir + "\Debug"
    if (Test-Path ".\bin\sigcheck.exe") {
        & .\bin\sigcheck.exe /accepteula -a -nobanner -e -c -h -q -s -r $("$env:PUBLIC\") 2> $null | ConvertFrom-Csv | ForEach-Object { $_ }
        & .\bin\sigcheck.exe /accepteula -a -nobanner -e -c -h -q -s -r $("$WinTempDir\") 2> $null | ConvertFrom-Csv | ForEach-Object { $_ }
        & .\bin\sigcheck.exe /accepteula -a -nobanner -e -c -h -q -s -r $("$WinDebugDir\") 2> $null | ConvertFrom-Csv | ForEach-Object { $_ }
        & .\bin\sigcheck.exe /accepteula -a -nobanner -e -c -h -q -s -r $("$env:APPDATA\") 2> $null | ConvertFrom-Csv | ForEach-Object { $_ }
        & .\bin\sigcheck.exe /accepteula -a -nobanner -e -c -h -q -s -r $("$env:TEMP\") 2> $null | ConvertFrom-Csv | ForEach-Object { $_ }
        & .\bin\sigcheck.exe /accepteula -a -nobanner -e -c -h -q -s -r $("$env:ProgramData\") 2> $null | ConvertFrom-Csv | ForEach-Object { $_ }
    }
}

<#
Ref: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1
- Example 15: Filter event log results
- Json datetime format: "TimeCreated":  "\/Date(1593955927331)\/"
- To convert to datetime: ([datetime]'1/1/1970').AddMilliseconds(1593955927331)
- Ref: https://social.technet.microsoft.com/Forums/ie/en-US/720aaf07-9da1-4f29-bd8a-718c198b7cb3/converting-datetime-values-from-json-file?forum=winserverpowershell
#>
function Get-PowershellJson {
    $Last60Days = (Get-Date) - (New-TimeSpan -Day 60)
    Get-WinEvent -LogName 'Windows PowerShell' | Where-Object { $_.TimeCreated -ge $Last60Days } | Select-Object Id, TimeCreated, LogName, ProcessId, LevelDisplayName, Message | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\pslogs.json
}


function Get-LastActivityviewJson {
    if (Test-Path ".\bin\lastactivityview.exe") {
        .\bin\lastactivityview.exe /scomma .\reports\lastactivity.csv
        Start-Sleep -Seconds 20
        Get-Content (Get-ChildItem .\reports\lastactivity.csv).FullName | ConvertFrom-Csv | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\lastactivity.json
        Start-Sleep -Seconds 5
    }
}


<#
Ref: https://www.nirsoft.net/utils/web_browser_addons_view.html
#>
function Get-BrowserAddonsJson {
    if (Test-Path ".\bin\BrowserAddonsView.exe") {
        .\bin\BrowserAddonsView.exe /scomma .\reports\addons.csv
        Start-Sleep -Seconds 10
        Get-Content (Get-ChildItem .\reports\addons.csv).FullName | ConvertFrom-Csv | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\addons.json
        Start-Sleep -Seconds 5
    }
}

<#
Ref: https://www.nirsoft.net/utils/cports.html
#>
function Get-NetworkingCsv {
    if (Test-Path ".\bin\cports.exe") {
        .\bin\cports.exe /scomma .\reports\net.csv
    }
}

function Get-NetworkingXml {
    if (Test-Path ".\bin\cports.exe") {
        .\bin\cports.exe /sxml .\reports\net.xml
    }
}

<#
# $a = (Get-NetTCPConnection | Select-Object State | Sort-Object State).State
# foreach ($it in $a){ $str = "{0}: {1}`n" -f $it, [int]$it; Write-Host $str}
# State table: https://sysnetdevops.com/2017/04/24/exploring-the-powershell-alternative-to-netstat/
#>
function Get-NetworkingJson {
    Get-NetTCPConnection | Select-Object @{
        l="ProcessName"; e = {
            Get-Process -Id $_.OwningProcess | Select-Object -ExpandProperty ProcessName
        }
    }, @{
        l="PID"; e = {$_.OwningProcess}
    }, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\net.json
}


# Process Module
# require administrator privileges
function ProcessCheck {
    try {
        Get-Process -IncludeUserName | Select-Object ProcessName, Id, UserName, Description, Company, Path | Format-Table -AutoSize | Out-String -width 1024 | Out-File -FilePath .\reports\process.txt
        # Get-Process -IncludeUserName | Select-Object ProcessName, Id, UserName, Description, Company, Path | Export-Csv -Path 1.csv
        Get-WmiObject Win32_Process | Select-Object ProcessId, ProcessName, CommandLine | Sort-Object -Property CommandLine | Format-Table -AutoSize | Out-String -width 1024 | Out-File -Append -FilePath .\reports\process.txt
        $ListPath = @(Get-Process | ForEach-Object {$_.Path} | Sort-Object | Select-Object -Unique)
        foreach ($ProcPath in $ListPath) {
            .\bin\sigcheck.exe -accepteula -nobanner -h -ct $ProcPath >> .\reports\procsig.csv
        }
    }
    catch {
        return $false
    }
    return $true
}
<#
Get info about process: imagehash, cmdline, path, authen code,..
Verified code:
0 = Valid
1 = ?
2 = NotSigned
3 = HashMismatch
#>
function Get-ProcSigJson {
    Get-Process -IncludeUserName | Select-Object Id, ProcessName, UserName, Description, Company, @{
        l="Verified"; e = {
            (Get-AuthenticodeSignature -FilePath $_.Path).Status
        }
    }, @{
        l="MD5"; e = {
            (Get-FileHash -Algorithm MD5 -Path $_.Path).Hash
        }
    }, @{
        l="SHA-1"; e = {
            (Get-FileHash -Algorithm SHA1 -Path $_.Path).Hash
        }
    }, @{
        l="SHA-256"; e = {
            (Get-FileHash -Algorithm SHA256 -Path $_.Path).Hash
        }
    }, @{
        l="CommandLine"; e = {
            $pid_ = $_.Id
            (Get-WmiObject Win32_Process -Filter "ProcessId='$pid_'").CommandLine
        }
    }, Path | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\proc.json
}


function InputValidation {
    param ( $username, $id )
    if ([string]::IsNullOrEmpty($username)) {
        return $false
    }
    if ([string]::IsNullOrEmpty($id)) {
        return $false
    }
    if ($username.length -gt 30 -or $username.length -lt 2) {
        return $false
    }
    if ($id.length -gt 6 -or $id.length -lt 1) {
        return $false
    }

    $tempUser = $username.ToCharArray();
    foreach ($chr in $tempUser) {
        if ($chr -notmatch "[a-zA-Z]") {
            return $false;
        }
    }

    $tempId = $id.ToCharArray();
    foreach ($chr in $tempId) {
        if ($chr -notmatch "[0-9]") {
            return $false;
        }
    }

    return $true;
}

<#
# Ref: https://poshgui.com/
#>
function GetUserInputForm {
    
    #$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $FormThongTinNhanVien                   = New-Object system.Windows.Forms.Form
    $FormThongTinNhanVien.ClientSize        = New-Object System.Drawing.Point(350,445) # 329,445
    $FormThongTinNhanVien.text              = "Malware Automation Check"
    $FormThongTinNhanVien.MaximizeBox       = $false
    $FormThongTinNhanVien.ControlBox        = $false
    $FormThongTinNhanVien.FormBorderStyle   = 'FixedDialog'
    $FormThongTinNhanVien.StartPosition     = 'CenterScreen'

    $lblHoTen                        = New-Object system.Windows.Forms.Label
    $lblHoTen.text                   = "Ho Ten (VD: Nguyen Van An)"
    $lblHoTen.AutoSize               = $true
    $lblHoTen.width                  = 25
    $lblHoTen.height                 = 10
    $lblHoTen.location               = New-Object System.Drawing.Point(30,24)
    $lblHoTen.Font                   = New-Object System.Drawing.Font('Arial',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $lblMaNhanVien                   = New-Object system.Windows.Forms.Label
    $lblMaNhanVien.text              = "Ma Nhan Su (VD: 100123)"
    $lblMaNhanVien.AutoSize          = $true
    $lblMaNhanVien.width             = 25
    $lblMaNhanVien.height            = 10
    $lblMaNhanVien.location          = New-Object System.Drawing.Point(30,92)
    $lblMaNhanVien.Font              = New-Object System.Drawing.Font('Arial',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $txtHoTen                        = New-Object system.Windows.Forms.TextBox
    $txtHoTen.multiline              = $false
    $txtHoTen.width                  = 285 #265
    $txtHoTen.height                 = 30
    $txtHoTen.location               = New-Object System.Drawing.Point(29,50) # 29,50
    $txtHoTen.Font                   = New-Object System.Drawing.Font('Arial',12)

    $txtMaNhanSu                     = New-Object system.Windows.Forms.TextBox
    $txtMaNhanSu.multiline           = $false
    $txtMaNhanSu.width               = 285 #265
    $txtMaNhanSu.height              = 30
    $txtMaNhanSu.location            = New-Object System.Drawing.Point(31,120) # 31,120
    $txtMaNhanSu.Font                = New-Object System.Drawing.Font('Arial',12)

    $gbKhoi                          = New-Object system.Windows.Forms.Groupbox
    $gbKhoi.height                   = 145
    $gbKhoi.width                    = 290 # 265
    $gbKhoi.location                 = New-Object System.Drawing.Point(31,197) # 31,197

    $btnHoanTat                      = New-Object system.Windows.Forms.Button
    $btnHoanTat.text                 = "Hoan Tat! Bat dau kiem tra"
    $btnHoanTat.width                = 240
    $btnHoanTat.height               = 51
    $btnHoanTat.location             = New-Object System.Drawing.Point(50,368) # 43,368
    $btnHoanTat.Font                 = New-Object System.Drawing.Font('Arial',13,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $btnHoanTat.DialogResult         = [System.Windows.Forms.DialogResult]::OK
    $FormThongTinNhanVien.AcceptButton = $btnHoanTat


    $rbExample1                       = New-Object system.Windows.Forms.RadioButton
    $rbExample1.text                  = "Example 1"
    $rbExample1.AutoSize              = $true
    $rbExample1.width                 = 104
    $rbExample1.height                = 20
    $rbExample1.location              = New-Object System.Drawing.Point(15,25) # New-Object System.Drawing.Point(28,26)
    $rbExample1.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $rbExample1.Checked               = $true

    $rbExample2                      = New-Object system.Windows.Forms.RadioButton
    $rbExample2.text                 = "Example 2"
    $rbExample2.AutoSize             = $true
    $rbExample2.width                = 104
    $rbExample2.height               = 20
    $rbExample2.location             = New-Object System.Drawing.Point(15,50) # New-Object System.Drawing.Point(28,60)
    $rbExample2.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rbExample3                         = New-Object system.Windows.Forms.RadioButton
    $rbExample3.text                    = "Example 3"
    $rbExample3.AutoSize                = $true
    $rbExample3.width                   = 104
    $rbExample3.height                  = 20
    $rbExample3.location                = New-Object System.Drawing.Point(15,75) # New-Object System.Drawing.Point(28,89)
    $rbExample3.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rbExample4                       = New-Object system.Windows.Forms.RadioButton
    $rbExample4.text                  = "Example 4"
    $rbExample4.AutoSize              = $true
    $rbExample4.width                 = 104
    $rbExample4.height                = 20
    $rbExample4.location              = New-Object System.Drawing.Point(15,100) # New-Object System.Drawing.Point(143,26)
    $rbExample4.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rbExample5                     = New-Object system.Windows.Forms.RadioButton
    $rbExample5.text                = "Example 5"
    $rbExample5.AutoSize            = $true
    $rbExample5.width               = 104
    $rbExample5.height              = 20
    $rbExample5.location            = New-Object System.Drawing.Point(110,25) # New-Object System.Drawing.Point(143,89)
    $rbExample5.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rbExample6                       = New-Object system.Windows.Forms.RadioButton
    $rbExample6.text                  = "Example 6"
    $rbExample6.AutoSize              = $true
    $rbExample6.width                 = 104
    $rbExample6.height                = 20
    $rbExample6.location              = New-Object System.Drawing.Point(110,50) # New-Object System.Drawing.Point(143,60)
    $rbExample6.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))


    $rbExample7                         = New-Object system.Windows.Forms.RadioButton
    $rbExample7.text                    = "Example 7"
    $rbExample7.AutoSize                = $true
    $rbExample7.width                   = 104
    $rbExample7.height                  = 20
    $rbExample7.location                = New-Object System.Drawing.Point(110,75) # New-Object System.Drawing.Point(100,114)
    $rbExample7.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))


    $rbExample8                         = New-Object system.Windows.Forms.RadioButton
    $rbExample8.text                    = "Example 8"
    $rbExample8.AutoSize                = $true
    $rbExample8.width                   = 104
    $rbExample8.height                  = 20
    $rbExample8.location                = New-Object System.Drawing.Point(110,100) # New-Object System.Drawing.Point(100,114)
    $rbExample8.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    # ------------------- start --------------------------------
    # Add new HCM Space
    $rbExample9                       = New-Object system.Windows.Forms.RadioButton
    $rbExample9.text                  = "Example 9"
    $rbExample9.AutoSize              = $true
    $rbExample9.width                 = 104
    $rbExample9.height                = 20
    $rbExample9.location              = New-Object System.Drawing.Point(210,25)
    $rbExample9.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rbExample10                       = New-Object system.Windows.Forms.RadioButton
    $rbExample10.text                  = "Example 10"
    $rbExample10.AutoSize              = $true
    $rbExample10.width                 = 104
    $rbExample10.height                = 20
    $rbExample10.location              = New-Object System.Drawing.Point(210,50)
    $rbExample10.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rbExample11                     = New-Object system.Windows.Forms.RadioButton
    $rbExample11.text                = "Example 11"
    $rbExample11.AutoSize            = $true
    $rbExample11.width               = 104
    $rbExample11.height              = 20
    $rbExample11.location            = New-Object System.Drawing.Point(210,75)
    $rbExample11.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rbExample12                       = New-Object system.Windows.Forms.RadioButton
    $rbExample12.text                  = "Example 12"
    $rbExample12.AutoSize              = $true
    $rbExample12.width                 = 104
    $rbExample12.height                = 20
    $rbExample12.location              = New-Object System.Drawing.Point(210,100)
    $rbExample12.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    # ------------------- end --------------------------------

    $lblGroup                        = New-Object system.Windows.Forms.Label
    $lblGroup.text                   = "Khu vuc"
    $lblGroup.AutoSize               = $true
    $lblGroup.width                  = 25
    $lblGroup.height                 = 10
    $lblGroup.location               = New-Object System.Drawing.Point(33,168)
    $lblGroup.Font                   = New-Object System.Drawing.Font('Arial',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $FormThongTinNhanVien.controls.AddRange(@($lblHoTen,$lblMaNhanVien,$txtHoTen,$txtMaNhanSu,$gbKhoi,$btnHoanTat,$lblGroup))
    $gbKhoi.controls.AddRange(@($rbExample1,$rbExample2,$rbExample3,$rbExample4,$rbExample5,$rbExample6,$rbExample7,$rbExample8,$rbExample10,$rbExample12,$rbExample11,$rbExample9))

    $FormThongTinNhanVien.Topmost = $true
    $FormThongTinNhanVien.Add_Shown({$txtHoTen.Select()})
    $FormThongTinNhanVien.Add_Shown({$txtMaNhanSu.Select()})

    do
    {
        $result = $FormThongTinNhanVien.ShowDialog()
        if  ((InputValidation -username $txtHoTen.text.Replace(' ', '') -id $txtMaNhanSu.text.Replace(' ', ''))) {
                break
        }
    } while($true)
    

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $full_name = $txtHoTen.Text
        $employee_id = $txtMaNhanSu.Text
        $group_name = ($gbKhoi.Controls | Where-Object{ $_.Checked }).Text
        return $full_name, $employee_id, $group_name
    }
    
    return 'God', '999999', 'Other'

}


function CredentialDecode {
    param ( $str='')
    return [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($str))
}

# Utilities Module
function ClientRegistering {
    param ( $EmployeeID='', $FullName='', $ReportName='', $GroupName='', $HostPlatform='')
    $uri = CredentialDecode -str $CRED_REGISTER
    try {
        $person = @{
            employee_id=$EmployeeID
            full_name=$FullName
            report_name=$ReportName
            group_name=$GroupName
            platform=$HostPlatform
        }
        $json = $person | ConvertTo-Json
        $response = Invoke-RestMethod $uri -Method Post -Body $json -ContentType 'application/json'
    }
    catch {
        return $false
    }

    return $response.message -match 'successfully'
}

function ClientSendReport {
    param ( $FilePath='' )
    try {
        $wc = New-Object System.Net.WebClient
        $uri = CredentialDecode -str $CRED_FILES
        $resp = $wc.UploadFile($uri, $FilePath)
        $enc = [System.Text.Encoding]::ASCII
    } catch {
        return $false
    }
    return $enc.GetString($resp) -match 'successfully'
}

# Compress all report file to .zip
# https://social.technet.microsoft.com/Forums/en-US/85013d18-a922-4c7b-8a83-197d0d5e3da7/can-we-add-a-filter-with-compressarchive-comdlet?forum=winserverpowershell
function Get-ZipReport {
    param ( $ZipFileName='')
    #Compress-Archive -Force -Path .\reports\* -DestinationPath .\upload\$ZipFileName
    #Get-ChildItem -Path .\reports\* -Recurse -File -Exclude *.csv | Compress-Archive -Force -DestinationPath .\upload\$ZipFileName
    .\bin\7z\7za.exe a -r .\upload\$ZipFileName .\reports\*.json | Out-Null
    return Test-Path .\upload\$ZipFileName
}

function Get-SystemInfoJson {
    systeminfo.exe /fo CSV | ConvertFrom-Csv | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\info.json
}

function Get-MacAddressJson {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\mac.json
}

<#
Ref: https://stackoverflow.com/a/46227004
#>
function Get-IPAddressJson {
    try {
        $ip = Get-NetIPConfiguration | Select-Object InterfaceIndex, IPv4Address, InterfaceAlias, InterfaceDescription, NetAdapter
        ForEach( $a in $ip ) {
            $a.Ipv4Address =  $a.Ipv4Address.IpAddress
            $a | Add-Member -type NoteProperty -name Status -value $a.NetAdapter.Status
            $a.PSObject.Properties.Remove('NetAdapter')
        }
        $ip | ConvertTo-Json | Out-File -FilePath .\reports\ip.json
    }
    catch {
        return $false
    }
    return $true
}

function CleaningData {
    Remove-Item .\bin\* -Force -Recurse
    Remove-Item .\upload\* -Force -Recurse
    Remove-Item .\reports\* -Force -Recurse
    Remove-Item * -Force -Recurse -Exclude $log_file;

	$Invocation = (Get-Variable MyInvocation -Scope 1).Value
	$Path =  $Invocation.MyCommand.Path
	#Remove-Item (Split-Path $Path) -Force -Recurse
	Remove-Item $Path -Force -Recurse
	#DEL $Path
}


# GLOBAL CONFIG
$CRED_FILES = 'aHR0cHM6Ly9leGFtcGxlLmNvbS9maWxlcw'
$CRED_REGISTER = 'aHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3Rlcg'
$CRED_PLATFORM = 'Windows'

function MainApp {
    # Make sure only one instance running.
    $proc_count = Get-Process | Where-Object {$_.ProcessName -like "MalAuto*"}
    if ($proc_count.Count -gt 1) {
        exit
    }

    # Checking version of Powershell, require: powershell 4 or over
    if ((($PSVersionTable).PSVersion).Major -lt 4) {
        Get-MessageBox -Message "This software is not supported on this operating system version!" -Title 'Error Running' -Type 'Error'
        CleaningData;
        exit
    }
    
    # Checking 3rd software available in .\bin directory
    CheckBinarys;
    
    # Checking and create necessary directory, eg: reports, upload,..
    InitDirectory;

    # Show input dialog, get input from user, generate report name, log name,..
    $full_name, $employee_id, $group_name = GetUserInputForm;
    $temp_name = Get-FileNameReport -FullName $full_name.Replace(' ', '') -EmployeeID $employee_id
    $report_file = $temp_name + '.zip'
    $log_file = $temp_name + '.log'

    # Register with server: try 5 times
    $count = 0
    do {
        $count++
        if ( ClientRegistering -EmployeeID $employee_id -FullName $full_name -ReportName $report_file -GroupName $group_name -HostPlatform $CRED_PLATFORM ) {
            Write-Logs -LogFile $log_file -Message "[+]: Register client with server: Ok!"
            break
        } else {
            Write-Logs -LogFile $log_file -Message "[-]: Register client with server: Failed!"
            Get-MessageBox -Message "Check your internet connection or firewall configuration!" -Title 'Client register failed' -Type 'Error'
            if ($count -eq 5) {
                CleaningData;
                exit
            }
        }
    } while ($true)

    Get-ChildItem -Path .\reports\ -Include * | Remove-Item
    Write-Logs -LogFile $log_file -Message "[+]: Clean old report files: Ok!"

    Get-SystemInfoJson;
    Get-MacAddressJson;
    Write-Logs -LogFile $log_file -Message "[+]: Get host infomation: Ok!"
    
    Get-AutorunscJson | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\autorun.json
    Write-Logs -LogFile $log_file -Message "[+]: Autoruns check: Ok!"
    
    Get-ProcSigJson;
    Write-Logs -LogFile $log_file -Message "[+]: Process check: Ok!"
    
    #Get-NetworkingCsv;
    #Get-NetworkingXml;
    Get-NetworkingJson;
    Write-Logs -LogFile $log_file -Message "[+]: Network check: Ok!"
    
    Get-FilesSigCkJson | ConvertTo-Json | Out-File -Encoding utf8 -FilePath .\reports\files.json
    Write-Logs -LogFile $log_file -Message "[+]: Files check: Ok!"

    Get-PowershellJson;
    Write-Logs -LogFile $log_file -Message "[+]: Logs Parsing: Ok!"

    Get-LastActivityviewJson;
    Write-Logs -LogFile $log_file -Message "[+]: Last Activity check: Ok!"
    
    Get-BrowserAddonsJson;
    Write-Logs -LogFile $log_file -Message "[+]: Browser add-on: Ok!"
    
    Copy-Item -Path $log_file -Destination .\reports\
    
    if (Get-ZipReport -ZipFileName $report_file) {
        Write-Logs -LogFile $log_file -Message "[+]: Compress Report: Ok!"
    } else {
        Write-Logs -LogFile $log_file -Message "[-]: Compress Report: Failed!"
        Get-MessageBox -Message 'Failed to compress report!' -Title 'Error' -Type 'Error'
    }
    
    # Send report file
    $count = 0
    $report_full_path = (Get-ChildItem .\upload\$report_file).FullName
    do {
        $count++
        if (ClientSendReport -FilePath $report_full_path) {
            Write-Logs -LogFile $log_file -Message "[+]: Send report: Ok!"
            Get-MessageBox -Message 'Hoan tat kiem tra virus/malware!' -Title 'Thong bao' -Type 'Asterisk'
            break
        } else {
            Write-Logs -LogFile $log_file -Message "[-]: Send report: Failed!"
            Get-MessageBox -Message 'Check your internet connection or firewall configuration!' -Title 'Send report failed' -Type 'Error'
            if ($count -eq 5) {
                break
            }
        }
    } while ($true)

    # always clean tools.
    CleaningData;
}

# Entry point
MainApp