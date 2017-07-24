# IISFortify-PS
# By Chris Campbell

# Based on https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12

# Logic Flow at Script End

function Restrict-Information {
	$appcmd = $($env:windir + "\system32\inetsrv\appcmd.exe")

	# Remove unnecessary IIS server information.
	Write-Output 'Removing IIS and ASP.NET server identification...'
	Write-Output '--------------------------------------------------------------------------------'
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/+[name='Remove_RESPONSE_Server']" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].patternSyntax:`"Wildcard`"" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].match.serverVariable:RESPONSE_Server" "/[name='Remove_RESPONSE_Server'].match.pattern:`"*`"" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].action.type:`"Rewrite`"" "/[name='Remove_RESPONSE_Server'].action.value:`" `"" /commit:apphost

	& $appcmd set config /section:httpProtocol "/-customHeaders.[name='X-Powered-By']"

	#HSTS header
	Write-Output 'Configuring HSTS header...'
	Write-Output '--------------------------------------------------------------------------------'
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='Strict-Transport-Security',value='max-age=31536000; includeSubDomains']"

	# Prevent framejacking.
	Write-Output 'Configuring other Security headers...'
	Write-Output '--------------------------------------------------------------------------------'
	& $appcmd set config /section:httpProtocol "/+customHeaders.[name='cache-control',value='private, max-age=0, no-cache']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Content-Type-Options',value='nosniff']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-XSS-Protection',value='1; mode=block']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Frame-Options',value='SAMEORIGIN']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Download-Options',value='noopen']"
}

Function Backup-Crypto {
	Write-Output 'Backing up crypto configuration to C:\temp\fortify.bkp...'
	Write-Output '--------------------------------------------------------------------------------'

    $reg = $($env:windir + "\system32\reg.exe")

    & $reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders" C:\temp\fortify_securityproviders.tmp
    & $reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002" C:\temp\fortify_ciphersuiteshex.tmp
    & $reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" C:\temp\fortify_ciphersuites.tmp
    Get-Content C:\temp\fortify*.tmp | Set-Content C:\temp\fortify.bkp
    Remove-Item C:\temp\fortify*.tmp
}

Function Harden-Crypto {
    $os = Get-WmiObject -class Win32_OperatingSystem

	Write-Output 'Configuring IIS with SSL/TLS deployment best practices...'
	Write-Output '--------------------------------------------------------------------------------'
	 
	# Disable Multi-Protocol Unified Hello
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'Multi-Protocol Unified Hello has been disabled.'
	 
	# Disable PCT 1.0
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'PCT 1.0 has been disabled.'
	 
	# Disable SSL 2.0
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'SSL 2.0 has been disabled.'
	 
	# Disable SSL 3.0
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'SSL 3.0 has been disabled.'

	# Disable TLS 1.0 for client and server SCHANNEL communications (Server 2012 R2+).
    if ([System.Version]$os.Version -gt [System.Version]'6.3') {
	    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
	    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force | Out-Null
	    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
	    Write-Output 'TLS 1.0 has been disabled.'
    }

    # Add and Enable TLS 1.0 for client and server SCHANNEL communications (Server 2008 R2).
    else {
	    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
	    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
	    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	    Write-Output 'TLS 1.0 has been enabled.'
    }

	# Add and Enable TLS 1.1 for client and server SCHANNEL communications.
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'TLS 1.1 has been enabled.'
	 
	# Add and Enable TLS 1.2 for client and server SCHANNEL communications.
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'TLS 1.2 has been enabled.'
	 
	# Re-create the ciphers key.
	New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null
	 
	# Disable insecure/weak ciphers.
	$insecureCiphers = @(
	  'DES 56/56',
	  'NULL',
	  'RC2 128/128',
	  'RC2 40/128',
	  'RC2 56/128',
	  'RC4 40/128',
	  'RC4 56/128',
	  'RC4 64/128',
	  'RC4 128/128'
	)
	ForEach ($insecureCipher in $insecureCiphers) {
	  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
	  $key.SetValue('Enabled', 0, 'DWord')
	  $key.close()
	  Write-Output "Weak cipher: $insecureCipher has been disabled."
	}
	 
	# Enable secure ciphers.
	$secureCiphers = @(
	  'AES 128/128',
	  'AES 256/256',
	  'Triple DES 168/168'
	)

	ForEach ($secureCipher in $secureCiphers) {
	  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
	  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	  $key.close()
	  Write-Output "Strong cipher: $secureCipher has been enabled."
	}

    # Set hash configuration.
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
 
    $secureHashes = @(
      'SHA',
      'SHA256',
      'SHA384',
      'SHA512'
    )

    ForEach ($secureHash in $secureHashes) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
      $key.close()
      Write-Host "Strong hash: $secureHash has been enabled."
    }
 
    # Set KeyExchangeAlgorithms configuration.
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
    $secureKeyExchangeAlgorithms = @(
      'Diffie-Hellman',
      'ECDH',
      'PKCS'
    )

    ForEach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
      $key.close()
      Write-Host "Key Exchange Algorithm: $secureKeyExchangeAlgorithm has been enabled."
    }
	 
	# Set cipher suites order as secure as possible.
    if ([System.Version]$os.Version -gt [System.Version]'10.0') {
        Write-Host "Applying Server 2016 cipher suite configuration..."
	    $cipherSuitesOrder = @(
          'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
          'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
          'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
          'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
          'TLS_RSA_WITH_AES_256_GCM_SHA384',
          'TLS_RSA_WITH_AES_128_GCM_SHA256',
          'TLS_RSA_WITH_AES_256_CBC_SHA256',
          'TLS_RSA_WITH_AES_128_CBC_SHA256',
          'TLS_RSA_WITH_AES_256_CBC_SHA',
          'TLS_RSA_WITH_AES_128_CBC_SHA'
	    )
    }

    elseif ([System.Version]$os.Version -gt [System.Version]'6.3') {
        Write-Host "Applying Server 2012 R2 cipher suite configuration..."
	    $cipherSuitesOrder = @(
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
	      'TLS_RSA_WITH_AES_256_CBC_SHA256',
	      'TLS_RSA_WITH_AES_128_CBC_SHA256'
	    )
    }

    else {
        Write-Host "Applying Server 2008 R2 cipher suite configuration..."
	    $cipherSuitesOrder = @(
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
	      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
	      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
	      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
	      'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
	      'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
	      'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
	      'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
	      'TLS_RSA_WITH_AES_256_CBC_SHA256',
	      'TLS_RSA_WITH_AES_256_CBC_SHA',
	      'TLS_RSA_WITH_AES_128_CBC_SHA256',
	      'TLS_RSA_WITH_AES_128_CBC_SHA'
	    )
    }
	$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
	New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
}

Write-Output '******************************'
Write-Output '*                            *'
Write-Output '* IISFortify-PS beginning... *'
Write-Output '*                            *'
Write-Output '******************************'

# Comment out any step that you do not wish to perform.
Restrict-Information
Backup-Crypto
Harden-Crypto

Write-Output '****************************'
Write-Output '*                          *'
Write-Output '* IISFortify-PS complete!  *'
Write-Output '*                          *'
Write-Output '****************************'