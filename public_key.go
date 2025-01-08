package apple

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
)

// AppleJWK represents Apple's JSON Web Key (JWK) structure
type AppleJWK struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

var AppleJWKs *AppleJWK

// FetchAppleJWKs fetches Apple's JWKs from their endpoint
func FetchAppleJWKs() (*AppleJWK, error) {
	if AppleJWKs != nil {
		return AppleJWKs, nil
	}
	const appleJWKURL = "https://appleid.apple.com/auth/keys"
	resp, err := http.Get(appleJWKURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Apple JWKs: %v", err)
	}
	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(&AppleJWKs); err != nil {
		return nil, fmt.Errorf("failed to decode Apple JWKs: %v", err)
	}

	return AppleJWKs, nil
}

// GetAppleRSAPublicKey parses the JWK and returns an RSA public key
func GetAppleRSAPublicKey(jwk AppleJWK, kid string) (*rsa.PublicKey, error) {
	for _, key := range jwk.Keys {
		if key.Kid == kid {
			// Decode the modulus (n) and exponent (e)
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode modulus (n): %v", err)
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode exponent (e): %v", err)
			}

			// Convert exponent to integer
			var eInt int
			if len(eBytes) == 3 {
				eInt = int(eBytes[0])<<16 | int(eBytes[1])<<8 | int(eBytes[2])
			} else if len(eBytes) == 1 {
				eInt = int(eBytes[0])
			} else {
				return nil, errors.New("unexpected exponent length")
			}

			// Create the RSA public key
			pubKey := &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: eInt,
			}
			return pubKey, nil
		}
	}
	return nil, fmt.Errorf("no matching key found for kid: %s", kid)
}
