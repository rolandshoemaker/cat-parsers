package main

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

func dnToMap(dn pkix.Name) map[string]interface{} {
	s := map[string]interface{}{}

	if len(dn.CommonName) > 0 {
		s["commonName"] = dn.CommonName
	}
	if len(dn.SerialNumber) > 0 {
		s["serialNumber"] = dn.SerialNumber
	}

	if len(dn.Country) > 0 {
		s["country"] = dn.Country
	}
	if len(dn.Organization) > 0 {
		s["organization"] = dn.Organization
	}
	if len(dn.OrganizationalUnit) > 0 {
		s["organizationalUnit"] = dn.OrganizationalUnit
	}
	if len(dn.Locality) > 0 {
		s["locality"] = dn.Locality
	}
	if len(dn.Province) > 0 {
		s["province"] = dn.Province
	}
	if len(dn.StreetAddress) > 0 {
		s["streetAddress"] = dn.StreetAddress
	}
	if len(dn.PostalCode) > 0 {
		s["postalCode"] = dn.PostalCode
	}

	return s
}

var pkType = map[x509.PublicKeyAlgorithm]string{
	x509.UnknownPublicKeyAlgorithm: "unknown",
	x509.RSA:                       "rsa",
	x509.DSA:                       "dsa",
	x509.ECDSA:                     "ecdsa",
}

func pkToMap(ki crypto.PublicKey) map[string]interface{} {
	m := map[string]interface{}{}
	switch pk := ki.(type) {
	case *rsa.PublicKey:
		m["n"] = fmt.Sprintf("%x", pk.N)
		m["e"] = pk.E
	case *dsa.PublicKey:
		m["p"] = fmt.Sprintf("%x", pk.P)
		m["q"] = fmt.Sprintf("%x", pk.Q)
		m["g"] = fmt.Sprintf("%x", pk.G)
		m["y"] = fmt.Sprintf("%x", pk.Y)
	case *ecdsa.PublicKey:
		c := pk.Curve.Params()
		m["curve"] = c.Name
		m["curveParams"] = map[string]interface{}{
			"p":       fmt.Sprintf("%x", c.P),
			"n":       fmt.Sprintf("%x", c.N),
			"b":       fmt.Sprintf("%x", c.B),
			"gx":      fmt.Sprintf("%x", c.Gx),
			"gy":      fmt.Sprintf("%x", c.Gy),
			"bitSize": c.BitSize,
		}
		m["x"] = fmt.Sprintf("%x", pk.X)
		m["y"] = fmt.Sprintf("%x", pk.Y)
	}
	return m
}

var kuToString = map[int]string{
	1: "DigitalSignature",
	2: "ContentCommitment",
	3: "KeyEncipherment",
	4: "DataEncipherment",
	5: "KeyAgreement",
	6: "CertSign",
	7: "CRLSign",
	8: "EncipherOnly",
	9: "DecipherOnly",
}

var ekuToString = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "ServerAuth",
	x509.ExtKeyUsageClientAuth:                 "ClientAuth",
	x509.ExtKeyUsageCodeSigning:                "CodeSigning",
	x509.ExtKeyUsageEmailProtection:            "EmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                "IPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSECUser",
	x509.ExtKeyUsageTimeStamping:               "TimeStamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "NetscapeServerGatedCrypto",
}

func ProcessCertificate(cert *x509.Certificate) map[string]interface{} {
	m := map[string]interface{}{
		"notBefore":          cert.NotBefore.UnixNano(),
		"notAfter":           cert.NotAfter.UnixNano(),
		"serialNumber":       fmt.Sprintf("%x", cert.SerialNumber.Bytes()),
		"basicConstraints":   cert.BasicConstraintsValid,
		"isCA":               cert.IsCA,
		"subject":            dnToMap(cert.Subject),
		"subjectHash":        fmt.Sprintf("%x", sha256.Sum256(cert.RawSubject)),
		"issuer":             dnToMap(cert.Issuer),
		"issuerHash":         fmt.Sprintf("%x", sha256.Sum256(cert.RawIssuer)),
		"signature":          fmt.Sprintf("%x", cert.Signature),
		"signatureAlgorithm": cert.SignatureAlgorithm.String(),
		"publicKey":          pkToMap(cert.PublicKey),
		"publicKeyAlgorithm": pkType[cert.PublicKeyAlgorithm],
		"publicKeyHash":      fmt.Sprintf("%x", sha256.Sum256(cert.RawSubjectPublicKeyInfo)),
		"version":            cert.Version,
		"tbsHash":            fmt.Sprintf("%x", sha256.Sum256(cert.RawTBSCertificate)),
	}

	keyUsages := []string{}
	for i := 1; i <= 9; i++ {
		if (cert.KeyUsage>>uint(i))&1 == 1 {
			keyUsages = append(keyUsages, kuToString[i])
		}
	}
	if len(keyUsages) > 0 {
		m["keyUsage"] = keyUsages
	}
	if len(cert.ExtKeyUsage) > 0 {
		extKeyUsages := []string{}
		for _, eku := range cert.ExtKeyUsage {
			extKeyUsages = append(extKeyUsages, ekuToString[x509.ExtKeyUsage(eku)])
		}
		m["extendedKeyUsage"] = extKeyUsages
	}

	if cert.MaxPathLen > 0 || cert.MaxPathLen == 0 && cert.MaxPathLenZero && cert.BasicConstraintsValid {
		m["maxPathLen"] = cert.MaxPathLen
	}

	certType := "leaf"
	if cert.IsCA && cert.BasicConstraintsValid {
		if bytes.Compare(cert.RawSubject, cert.RawIssuer) == 0 {
			certType = "root"
		} else {
			certType = "intermediate"
		}
	}
	m["type"] = certType

	if len(cert.DNSNames) > 0 {
		m["dnsNames"] = cert.DNSNames
	}
	if len(cert.IPAddresses) > 0 {
		m["ipAddresses"] = cert.IPAddresses
	}
	if len(cert.EmailAddresses) > 0 {
		m["emailAddresses"] = cert.EmailAddresses
	}

	if cert.AuthorityKeyId != nil {
		m["akid"] = fmt.Sprintf("%x", cert.AuthorityKeyId)
	}
	if cert.SubjectKeyId != nil {
		m["skid"] = fmt.Sprintf("%x", cert.SubjectKeyId)
	}

	if len(cert.OCSPServer) > 0 {
		m["ocspServers"] = cert.OCSPServer
	}
	if len(cert.IssuingCertificateURL) > 0 {
		m["issuingCertificateURLs"] = cert.IssuingCertificateURL
	}
	if len(cert.CRLDistributionPoints) > 0 {
		m["crlURLs"] = cert.CRLDistributionPoints
	}

	if len(cert.PermittedDNSDomains) > 0 {
		m["nameConstraints"] = cert.PermittedDNSDomains
		m["nameConstraintsCritical"] = cert.PermittedDNSDomainsCritical
	}

	if len(cert.PolicyIdentifiers) > 0 {
		policyOIDs := []string{}
		for _, oid := range cert.PolicyIdentifiers {
			policyOIDs = append(policyOIDs, oid.String())
		}
		m["policyIdentifiers"] = policyOIDs
	}

	return m
}
