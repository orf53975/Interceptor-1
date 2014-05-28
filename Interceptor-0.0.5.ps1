# Interceptor Proof of Concept
# Created By Casey Smith
# 04-28-2014
# 0.0.4
# Rewrite Sockets and Streams
# Proof of Concept 
# TODO
# 


function createCertificate([string] $certSubject, [bool] $isCA)
{
$CAsubject = $certSubject
$dn = new-object -com "X509Enrollment.CX500DistinguishedName"
$dn.Encode( "CN=" + $CAsubject, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)

# Create a new Private Key
$key = new-object -com "X509Enrollment.CX509PrivateKey"
$key.ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
# Set CAcert to 1 to be used for Signature
if($isCA)
	{
		$key.KeySpec = 2 
	}
else
	{
		$key.KeySpec = 1
	}
$key.Length = 1024
$key.MachineContext = 1
$key.Create() 
 
# Create Attributes
$serverauthoid = new-object -com "X509Enrollment.CObjectId"
$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
$ekuoids.add($serverauthoid)
$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
$ekuext.InitializeEncode($ekuoids)

$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
$cert.InitializeFromPrivateKey(2, $key, "")
$cert.Subject = $dn
$cert.Issuer = $cert.Subject
$cert.NotBefore = get-date
$cert.NotAfter = $cert.NotBefore.AddDays(90)
$cert.X509Extensions.Add($ekuext)
if ($isCA)
{
	$basicConst = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
	$basicConst.InitializeEncode("true", 1)
	$cert.X509Extensions.Add($basicConst)
}
else
{              
	$signer = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__InterCeptor_Trusted_Root" })
	$signerCertificate =  new-object -com "X509Enrollment.CSignerCertificate"
	$signerCertificate.Initialize(1,0,4, $signer.Thumbprint)
	$cert.SignerCertificate = $signerCertificate
}
$cert.Encode()

$enrollment = new-object -com "X509Enrollment.CX509Enrollment"
$enrollment.InitializeFromRequest($cert)
$certdata = $enrollment.CreateRequest(0)
$enrollment.InstallResponse(2, $certdata, 0, "")

if($isCA)
{              
                                
	# Need a Better way to do this...
	$CACertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__InterCeptor_Trusted_Root" })
	# Install CA Root Certificate
	$StoreScope = "LocalMachine"
	$StoreName = "Root"
	$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
	$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
	$store.Add($CACertificate)
	$store.Close()
                                
}
else
{
	return (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $CAsubject })
} 
     
}
#GetOutput

function GetOutput 
{ 
    ## Create a buffer to receive the response 
    $buffer = new-object System.Byte[] 1024 
    $encoding = new-object System.Text.AsciiEncoding

    $outputBuffer = "" 
    $foundMore = $false

    ## Read all the data available from the stream, writing it to the 
    ## output buffer when done. 
    do 
    { 
        ## Allow data to buffer for a bit 
        start-sleep -m 10

        ## Read what data is available 
        $foundmore = $false 
        $stream.ReadTimeout = 10

        do 
        { 
            try 
            { 
                $read = $stream.Read($buffer, 0, 1024)

                if($read -gt 0) 
                { 
                    $foundmore = $true 
                    $outputBuffer += ($encoding.GetString($buffer, 0, $read)) 
                } 
            } catch { $foundMore = $false; $read = 0 } 
        } while($read -gt 0) 
    } while($foundmore)

    $outputBuffer 
	
}

#Forward SSL Request
function ForwardSSLRequest([string]$remoteHost, [string] $SSLRequest)
{
		
        [int] $port = 443
        [int] $commandDelay = 10
		$currentInput = $SSLRequest
		
		write-host "Connecting to $remoteHost on port $port" -fore Yellow
		$socket = new-object System.Net.Sockets.TcpClient($remoteHost, $port)
		$stream = $socket.GetStream() 
		$sslStream = New-Object System.Net.Security.SslStream $stream,$false 
        $sslStream.AuthenticateAsClient($remoteHost) 
        $stream = $sslStream
		
		$writer = new-object System.IO.StreamWriter $stream
		
		while($true) 
		{	 
       
        foreach($line in $currentInput) 
            { 
                $writer.WriteLine($line) 
                $writer.Flush() 
                Start-Sleep -m $commandDelay 
				$result = GetOutput
            }

            break 
        } 
 
	$result
    ## Close the streams 
    $writer.Close() 
    $stream.Close()
		
}

# GetOutput
function GetSSLOutput ([System.Net.Security.SslStream] $stream) 
{ 
	write-host "Inside GetOutput" -fore Green
    ## Create a buffer to receive the response 
    $buffer = new-object System.Byte[] 1024 
    $encoding = new-object System.Text.AsciiEncoding
    $outputBuffer = "" 
    $foundMore = $false
	Try
	{
    ## Read all the data available from the stream, writing it to the 
    ## output buffer when done. 
    do 
    { 
        ## Allow data to buffer for a bit 
        start-sleep -m 500

        ## Read what data is available 
        $foundmore = $false 
        $stream.ReadTimeout = 500

        do 
        { 
            try 
            { 
                $read = $stream.Read($buffer, 0, 1024)

                if($read -gt 0) 
                { 
                    $foundmore = $true 
                    $outputBuffer += ($encoding.GetString($buffer, 0, $read)) 
                } 
            } catch { $foundMore = $false; $read = 0 } 
        } while($read -gt 0) 
    } while($foundmore)
	
	$outputBuffer 
	
	}
	Catch
	{
		write-host $error[0]
	}
}

#Define HTTPProcessing Function
function DoHttpProcessing([System.Net.Sockets.TcpClient] $HTTPclient)
{
	$HTTPreqtsb = New-Object System.Text.StringBuilder
	$SSLreqtsb = New-Object System.Text.StringBuilder
	Try
	{
	$clientStream = $HTTPclient.GetStream()
	$outStream = $clientStream
	$clientStreamReader = New-Object System.IO.StreamReader $ClientStream
	
	do {
		$line = $clientStreamReader.ReadLine()
		[void]$HTTPreqtsb.AppendLine($line)
	} while ($line -and $line -ne ([char]4))
	
	[string[]] $requestArray = ($HTTPreqtsb -split '[\r\n]') |? {$_} 
	[string[]] $methodParse = $requestArray[0] -split " "
	
	#Begin SSL MITM IF Request Contains CONNECT METHOD
	if($methodParse[0] -ceq "CONNECT")
	{
		[string[]] $domainParse = $methodParse[1].Split(":")
		write-host $domainParse[0] -fore Yellow
		
		$connectStreamWriter = New-Object System.IO.StreamWriter $clientStream
		$connectStreamWriter.WriteLine("HTTP/1.1 200 Connection Established")
		$connectStreamWriter.WriteLine("TimeStamp:" + [System.DateTime]::Now.ToString())
		$connectStreamWriter.WriteLine()
		$connectStreamWriter.Flush()
		
		$sslStream = New-Object System.Net.Security.SslStream($clientStream , $false)
		
		
		
		Try
		{       
			$sslcertfake = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $domainParse[0]  })
			if ($sslcertfake -eq $null)
			{
				$sslcertfake =  createCertificate $domainParse[0] $false
			}
			
			$sslStream.AuthenticateAsServer($sslcertfake, 0, [System.Security.Authentication.SslProtocols]::Ssl3 , 1)
		}
		Catch
		{
			write-host $error[0]
		}
		
		$SSLRequest = GetSSLOutput $sslStream
		write-host $SSLRequest -fore Cyan
		
		$SSLresponse = ForwardSSLRequest $domainParse[0] $SSLRequest.ToString()
		write-host $SSLresponse -fore Magenta
		
		$enc = [system.Text.Encoding]::UTF8
		$sslretData = $enc.GetBytes($SSLresponse) 
		$sslStream.Write($sslretData)
		
		
		
	}# End SSL Establishment  Now Process Each request and Write Results back to the stream
	
	}# End HTTPProcessing Block
	Catch
	{
		write-host $error[0] 
	}
	Finally
	{
		$clientStreamReader.Close()
		$clientStream.Close()		
		
	}
                
}

#Create and Install the CACert
$CAcertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root"  })
if ($CACertificate -eq $null)
{
createCertificate "__Interceptor_Trusted_Root" $true
}

#Start Proxy Server
# HTTPListener 
$BUFFER_SIZE = 2048
$port=8081
$endpoint = New-Object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
$listener = New-Object System.Net.Sockets.TcpListener $endpoint
$listener.Start()
$rcvBuffer = New-Object byte[] $BUFFER_SIZE
$bytesRcvd = 0


while($true){
                $client = New-Object System.Net.Sockets.TcpClient
                $reqString
                Try
                {                              
                    $client = $listener.AcceptTcpClient()
                    $reqString = DoHttpProcessing($client)
                }
                Catch [System.Exception]
                {
                    write-host $error[0] 
                }
                Finally
                {
                    $client.Close()
                }

}
