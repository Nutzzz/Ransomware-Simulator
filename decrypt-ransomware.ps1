<#
Ransomware-Simulator PowerShell Decrypter
.Description
This PowerShell script decrypts files using an X.509 public key certificate.
It will decrypt the files that are encrypted by the encryption script. It's configured to decrypt files on the lowest drive letter first (e.g. Z:). This allows you to control what share is being decrypted.
I recommend only having one share mapped to ensure only one share is decrypted.
.Instructions
You can copy your certificate's thumbprint to line 26 below, or allow the script to check for a file created by the encryption script.





.Notes

Credit to Ryan Ries for developing the decryption and filestream scriptblock.
http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx
.
Provided by WatchPoint Data under the MIT license.
#>


# Global variables

  # The certificate thumbprint to use
$CERT_THUMB = "THUMBPRINTGOESHERE"
  # Automatically use the first certificate found
$CERT_AUTO = $False
  # Set a file to load the last used cert thumbprint from encrypt script
$CERT_FILE = "$Env:TEMP\ransom\cert.txt"

  # Remove extension from decrypted files
$RENAME = $True
  # Set the extension to use
$RENAME_EXT = ".ransom"
  # Set a file to load the last used extension from encrypt script
$RENAME_EXT_FILE = "$Env:TEMP\ransom\ext.txt"

  # Set a file to load the network drives used from encrypt script
$DRIVES_FILE = "$Env:TEMP\ransom\drives.csv"

  # Use local directory to work on encrypted files
$USE_LOCAL_DIR = $True
  # Set the local directory to use
$LOCAL_DIR = "$Env:TEMP\ransom\work"


# Warn if run as admin
If ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')
{
    Write-Warning "NOTE: Currently running as Administrator; user network drives won't be found."
}

# Define the cert to use for decryption
If (-not [string]::IsNullOrEmpty($CERT_THUMB))
{
    $Cert = $(Get-ChildItem $("Cert:\CurrentUser\My\" + $CERT_THUMB) -ErrorAction SilentlyContinue)
}
If ($Cert.PrivateKey -eq $Null -or $Cert.HasPrivateKey -eq $False)
{
    If (Test-Path -Path "$CERT_FILE" -PathType Leaf)
    {
      # Use cert from encryption script
        $CERT_THUMB = Get-Content "$CERT_FILE" | Select -First 1
        $Cert = $(Get-ChildItem $("Cert:\CurrentUser\My\" + $CERT_THUMB) -ErrorAction SilentlyContinue)
    } ElseIf ($CERT_AUTO -eq 1) {
        $Cert = $(Get-ChildItem "Cert:\CurrentUser\My\" | Select-Object -First 1)
    }
}
If ($Cert.PrivateKey -eq $Null -or $Cert.HasPrivateKey -eq $False)
{
    Write-Error "The supplied certificate does not contain a private key, or it could not be accessed."
    Exit
}

If (Test-Path -Path "$DRIVES_FILE" -PathType Leaf)
{
  # Use drives from encryption script
    $netdrives = Import-CSV -Path "$DRIVES_FILE"
} Else {
  # Enumerate drives
    $psdrives = Get-PSDrive

  # Find network drives
    $netdrives = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($d in $psdrives)
    {
        if ($d.Root -ne $Null -and $d.DisplayRoot -ne $Null)
        {
            $netdrives.Add($d)
        }
    }
}

If (Test-Path -Path "$RENAME_EXT_FILE" -PathType Leaf)
{
  # Import rename extension
    $RENAME = $True
    $RENAME_EXT = Get-Content "$RENAME_EXT_FILE" | Select -First 1
    If ([string]::IsNullOrEmpty($RENAME_EXT) -or (-not $RENAME_EXT.StartsWith(".")))
    {
        $RENAME = $False
    }
}

# Enumerate files on the network drives
foreach ($n in $netdrives)
{
    If ($n)
    {
      # Decrypt files and ignore directories
        $FilesToDecrypt = Get-ChildItem -Path $n.Root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object{!($_.PSIsContainer)} | % {$_.FullName}
    } Else {
        Write-Host "File not accessible"
    }
}

If ($USE_LOCAL_DIR -eq 1)
{
    New-Item -Path "$LOCAL_DIR" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
}

# Decryption and filestream function
Function Decrypt-File
{
    Param([Parameter(mandatory=$true)][string]$FileToDecrypt,
          [Parameter(mandatory=$true)][string]$FileToWrite,
          [Parameter(mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    Try {
        [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography")
    } Catch {
        Write-Error "Could not load required assembly."
        Exit
    }

    If ((Get-Item "$FileToDecrypt").length -lt 256)
    {
        Write-Warning "Unable to process files smaller than 256 bytes."
        Return
    }

    $AesProvider                = New-Object System.Security.Cryptography.AesManaged
    $AesProvider.KeySize        = 256
    $AesProvider.BlockSize      = 128
    $AesProvider.Mode           = [System.Security.Cryptography.CipherMode]::CBC
    [Byte[]]$LenKey             = New-Object Byte[] 4
    [Byte[]]$LenIV              = New-Object Byte[] 4

    Try {
        $FileStreamReader = New-Object System.IO.FileStream([System.IO.FileInfo]"$FileToDecrypt", [System.IO.FileMode]::Open)
    } Catch {
        Write-Warning "Unable to open input file for reading."       
        Return
    }

    $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($LenKey, 0, 3)                            | Out-Null
    $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($LenIV,  0, 3)                            | Out-Null
    [Int]$LKey            = [System.BitConverter]::ToInt32($LenKey, 0)
    [Int]$LIV             = [System.BitConverter]::ToInt32($LenIV,  0)
    [Int]$StartC          = $LKey + $LIV + 8
    [Int]$LenC            = [Int]$FileStreamReader.Length - $StartC
    [Byte[]]$KeyEncrypted = New-Object Byte[] $LKey
    [Byte[]]$IV           = New-Object Byte[] $LIV
    $FileStreamReader.Seek(8, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($KeyEncrypted, 0, $LKey)                  | Out-Null
    $FileStreamReader.Seek(8 + $LKey, [System.IO.SeekOrigin]::Begin) | Out-Null
    $FileStreamReader.Read($IV, 0, $LIV)                             | Out-Null
    [Byte[]]$KeyDecrypted = $Cert.PrivateKey.Decrypt($KeyEncrypted, $false)
    If ($KeyDecrypted -eq $Null)
    {
        Write-Warning "Unable to decrypt file."
        Return
    }
    $Transform = $AesProvider.CreateDecryptor($KeyDecrypted, $IV)
    If ($Transform -eq $Null)
    {
        Write-Warning "Unable to decrypt file."
        Return
    }

    Try {
        $FileStreamWriter = New-Object System.IO.FileStream([System.IO.FileInfo]"$FileToWrite", [System.IO.FileMode]::Create)
    } Catch {
        Write-Warning "Unable to open output file for writing $($FileToWrite)"
        $FileStreamReader.Close()
        Return
    }

    [Int]$Count  = 0
    [Int]$Offset = 0
    [Int]$BlockSizeBytes = $AesProvider.BlockSize / 8
    [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)

    Do {
        $Count   = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
        $Offset += $Count
        $CryptoStream.Write($Data, 0, $Count)
    } While ($Count -gt 0)

    $CryptoStream.FlushFinalBlock()
    $CryptoStream.Close()
    $FileStreamWriter.Close()
    $FileStreamReader.Close()

    If ($USE_LOCAL_DIR -eq 1 -and $(Get-Item "$FileToDecrypt").length -ne 0)
    {
        Copy-Item -Path "$FileToWrite" -Destination "$FileToDecrypt" -Force
    }
}

# Logic to decrypt files
foreach ($infile in $FilesToDecrypt)
{
    If ($RENAME -eq 1 -and $([System.IO.Path]::GetExtension($infile)) -eq $RENAME_EXT)
    {
        Rename-Item -Path "$infile" -NewName "$([System.IO.Path]::GetFilenameWithoutExtension($infile))"
        $infile = "$([System.IO.Path]::GetDirectoryName($infile))\$([System.IO.Path]::GetFilenameWithoutExtension($infile))"
    }
    If ($USE_LOCAL_DIR)
    {
        $outfile = "$LOCAL_DIR\$([System.IO.Path]::GetFileName($infile))"
    } Else {
        $outfile = $infile
    }

    Write-Host "Decrypting $($infile)"
    Decrypt-File "$infile" "$outfile" $Cert
}

Write-Host "Decryption complete."
Exit
