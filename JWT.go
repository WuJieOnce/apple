package apple

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"time"
)

// GenerateAuthorizationJWT 生成 Apple App Store Server API 的 JWT
func GenerateAuthorizationJWT(Kid, Bid, Iss, privateKeyStr string) (string, error) {
	// 解析 PEM 格式的私钥
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("failed to parse private key: invalid PEM format")
	}

	// 解析 EC 私钥
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse EC private key: %v", err)
	}

	// 创建 JWT 的 Header 和 Claims
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": Iss,                              // Apple 团队 ID
		"iat": now.Unix(),                       // 当前时间戳
		"exp": now.Add(30 * time.Minute).Unix(), // 过期时间（30 分钟）
		"aud": "appstoreconnect-v1",             // 固定值 appstoreconnect-v1
		"bid": Bid,
	}

	// 创建 JWT
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = Kid // 设置 Header 的 kid（密钥 ID）

	// 使用私钥签名
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %v", err)
	}

	return signedToken, nil
}

// VerifyJWT verifies the JWT signature using the Apple JWK
func VerifyJWT(jws string) error {
	// Fetch Apple's JWKs
	jwk, err := FetchAppleJWKs()
	if err != nil {
		return fmt.Errorf("failed to fetch Apple JWKs: %v", err)
	}

	// Parse the JWT to extract the header and kid
	token, _, err := jwt.NewParser().ParseUnverified(jws, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %v", err)
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return errors.New("kid not found in JWT header")
	}

	// Get the RSA public key for the given kid
	pubKey, err := GetAppleRSAPublicKey(*jwk, kid)
	if err != nil {
		return fmt.Errorf("failed to get RSA public key: %v", err)
	}

	// Verify the JWT signature
	parsedToken, err := jwt.Parse(jws, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token uses the correct signing method
		if _, ok = token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return fmt.Errorf("failed to verify JWT: %v", err)
	}

	// Check if the token is valid
	if !parsedToken.Valid {
		return errors.New("invalid JWT")
	}

	return nil
}

// DecodeJWSTransaction decodes the payload of a JWSTransaction
func DecodeJWSTransaction(jws string) (*SubscriptionInfo, error) {
	// Split the JWT into three parts: header, payload, signature
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (Base64 URL encoded)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	// Unmarshal the JSON payload into the struct
	var transaction SubscriptionInfo
	if err = json.Unmarshal(payload, &transaction); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	return &transaction, nil
}

// VerifyJWSTransaction verifies the signature of the JWSTransaction
func VerifyJWSTransaction(jws string) (*SubscriptionInfo, error) {
	// Fetch Apple's JWKs
	jwk, err := FetchAppleJWKs()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Apple JWKs: %v", err)
	}

	// Parse the JWT to extract the header and kid
	token, _, err := jwt.NewParser().ParseUnverified(jws, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %v", err)
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid not found in JWT header")
	}

	// Get the ECDSA public key for the given kid
	pubKey, err := GetAppleRSAPublicKey(*jwk, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA public key: %v", err)
	}

	// Verify the JWT signature
	parsedToken, err := jwt.ParseWithClaims(jws, &SubscriptionInfo{}, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %v", err)
	}

	// Assert the claims as JWSTransactionPayload
	payload, ok := parsedToken.Claims.(*SubscriptionInfo)
	if !ok {
		return nil, fmt.Errorf("failed to parse JWT claims as JWSTransactionPayload")
	}

	return payload, nil
}
