package main

import "crypto/x509"

func ProcessChain(chain []*x509.Certificate) map[string]interface{} {
	m := map[string]interface{}{
		"length": len(chain),
	}
	byteSize := 0
	for _, c := range chain {
		byteSize += len(c.Raw)
	}
	m["size"] = byteSize
	return m
}
