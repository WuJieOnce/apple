package apple

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"time"
)

type OfferIdentifier string
type Timestamp int64

func (t Timestamp) Time() *time.Time {
	milli := time.UnixMilli(int64(t))
	return &milli
}

// ToNumericDate 将 Timestamp 转换为 jwt.NumericDate
func (t Timestamp) ToNumericDate() *jwt.NumericDate {
	return jwt.NewNumericDate(time.UnixMilli(int64(t)))
}

type JWSRenewalInfoDecodedPayload struct {
	// Transaction identifiers
	OriginalTransactionId string `json:"originalTransactionId"` // 与此交易关联的原始购买的交易标识符。
	TransactionId         string `json:"transactionId"`         // 交易的唯一标识符，例如应用内购买、恢复购买或订阅续订。
	WebOrderLineItemId    string `json:"webOrderLineItemId"`    // 跨设备订阅购买事件的唯一标识符，包括订阅续订。

	// App information
	BundleId string `json:"bundleId"` // The bundle identifier of an app.

	// Account information
	AppAccountToken *string `json:"appAccountToken"` // 将交易与您服务上的客户关联起来的 UUID。

	// Product information
	ProductId                   string `json:"productId"`                   // 应用内购买的产品标识符。
	Type                        string `json:"type"`                        // 应用内购买的产品类型。
	SubscriptionGroupIdentifier string `json:"subscriptionGroupIdentifier"` // 订阅所属订阅组的标识符。
	Quantity                    *int32 `json:"quantity"`                    // 购买的消耗品的数量。

	// Product price and currency
	Price    *int64 `json:"price"`    // 系统在交易中记录的应用内购买的价格（以毫为单位）。
	Currency string `json:"currency"` // 订阅的renewalPrice的货币代码。

	// Storefront information
	Storefront   string `json:"storefront"`   // 代表与购买的 App Store 店面关联的国家或地区的三字母代码。
	StorefrontId string `json:"storefrontId"` // Apple 定义的值，用于唯一标识 App Store 店面。

	// Subscription offers
	EligibleWinBackOfferIds []OfferIdentifier `json:"eligibleWinBackOfferIds"` // 客户有资格获得的赢回优惠 ID 列表。
	OfferType               int32             `json:"offerType"`               // 订阅优惠的类型。
	OfferDiscountType       string            `json:"offerDiscountType"`       // 折扣优惠的付款方式。

	// Purchase dates
	OriginalPurchaseDate        Timestamp `json:"originalPurchaseDate"`        // 与原始交易标识符关联的交易的购买日期。
	PurchaseDate                Timestamp `json:"purchaseDate"`                // App Store 向客户的帐户收取购买、恢复产品、订阅或订阅过期后续订费用的时间。
	RecentSubscriptionStartDate Timestamp `json:"recentSubscriptionStartDate"` // 一系列订阅购买中自动续订订阅的最早开始日期，忽略 60 天或更短时间的所有付费服务失效。

	// Billing status
	IsInBillingRetryPeriod bool      `json:"isInBillingRetryPeriod"` // 布尔值，指示 App Store 是否正在尝试自动续订过期的订阅。
	GracePeriodExpiresDate Timestamp `json:"gracePeriodExpiresDate"` // 订阅续订的计费宽限期到期的时间。

	// Subscripton renewal and expiration
	AutoRenewStatus    int32     `json:"autoRenewStatus"`    // 自动续订订阅的续订状态。0：自动续订已关闭。客户已关闭订阅自动续订，当前订阅期结束后不会续订。1：自动续订已开启。订阅将在当前订阅期结束时续订。
	AutoRenewProductId string    `json:"autoRenewProductId"` // 在下一个计费周期续订的产品的产品标识符。
	ExpirationIntent   int32     `json:"expirationIntent"`   // 订阅过期的原因。
	ExpiresDate        Timestamp `json:"expiresDate"`        // 自动续订订阅购买到期或续订的 UNIX 时间（以毫秒为单位）。
	IsUpgraded         bool      `json:"isUpgraded"`         // 一个布尔值，指示客户是否升级到另一个订阅。
	RenewalDate        Timestamp `json:"renewalDate"`        // 最近购买的自动续订订阅到期的 UNIX 时间（以毫秒为单位）。
	RenewalPrice       int64     `json:"renewalPrice"`       // 在下一个计费周期续订的自动续订订阅的续订价格（以毫为单位）。

	// Family Sharing
	InAppOwnershipType string `json:"inAppOwnershipType"` // 描述交易是否由客户购买，或者是否可以通过家庭共享提供给客户的字符串。

	// Price increase status
	PriceIncreaseStatus int32 `json:"priceIncreaseStatus"` // 指示自动续订订阅是否会涨价的状态。

	// Revocation date and reason
	RevocationDate   Timestamp `json:"revocationDate"`   // App Store 退款或从家庭共享中撤销交易的 UNIX 时间（以毫秒为单位）。
	RevocationReason string    `json:"revocationReason"` // 交易退款的原因。

	// Transaction reason
	TransactionReason string `json:"transactionReason"` // 购买交易的原因，表明是客户的购买还是系统发起的自动续订订阅的续订。

	// JWS signature date
	SignedDate Timestamp `json:"signedDate"` // App Store 签署 JSON Web 签名 (JWS) 数据的 UNIX 时间（以毫秒为单位）。

	Environment     string `json:"environment"`     // 服务器环境，沙箱或生产环境。
	OfferIdentifier string `json:"offerIdentifier"` // 优惠代码或促销优惠标识符。
}

// GetExpirationTime 实现了 jwt.Claims 的 GetExpirationTime 方法
func (J *JWSRenewalInfoDecodedPayload) GetExpirationTime() (*jwt.NumericDate, error) {
	if J.ExpiresDate == 0 {
		return nil, errors.New("expiration time not set")
	}
	return J.ExpiresDate.ToNumericDate(), nil
}

// GetIssuedAt 实现了 jwt.Claims 的 GetIssuedAt 方法
func (J *JWSRenewalInfoDecodedPayload) GetIssuedAt() (*jwt.NumericDate, error) {
	if J.SignedDate == 0 {
		return nil, errors.New("issued at time not set")
	}
	return J.SignedDate.ToNumericDate(), nil
}

// GetNotBefore 实现了 jwt.Claims 的 GetNotBefore 方法
func (J *JWSRenewalInfoDecodedPayload) GetNotBefore() (*jwt.NumericDate, error) {
	// 假设 NotBefore 时间未明确提供，可返回 nil 或自定义逻辑
	return nil, nil
}

// GetIssuer 实现了 jwt.Claims 的 GetIssuer 方法
func (J *JWSRenewalInfoDecodedPayload) GetIssuer() (string, error) {
	// 假设 Apple 的发行者是固定的 "Apple"
	return "Apple", nil
}

// GetSubject 实现了 jwt.Claims 的 GetSubject 方法
func (J *JWSRenewalInfoDecodedPayload) GetSubject() (string, error) {
	// 假设 Subject 是 BundleId
	if J.BundleId == "" {
		return "", errors.New("subject (bundleId) not set")
	}
	return J.BundleId, nil
}

// GetAudience 实现了 jwt.Claims 的 GetAudience 方法
func (J *JWSRenewalInfoDecodedPayload) GetAudience() (jwt.ClaimStrings, error) {
	// 假设 Audience 是 ProductId
	if J.ProductId == "" {
		return nil, errors.New("audience (productId) not set")
	}
	return jwt.ClaimStrings{J.ProductId}, nil
}

// JWSRenewalInfoDecoded decodes the payload of a JWSRenewalInfo
func JWSRenewalInfoDecoded(jws string) (*JWSRenewalInfoDecodedPayload, error) {
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
	var transaction = JWSRenewalInfoDecodedPayload{}
	if err = json.Unmarshal(payload, &transaction); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	return &transaction, nil
}

func VerifyJWSRenewalInfo(jws string) (*JWSRenewalInfoDecodedPayload, error) {
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
	parsedToken, err := jwt.ParseWithClaims(jws, &JWSRenewalInfoDecodedPayload{}, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %v", err)
	}

	// Assert the claims as JWSTransactionPayload
	payload, ok := parsedToken.Claims.(*JWSRenewalInfoDecodedPayload)
	if !ok {
		return nil, fmt.Errorf("failed to parse JWT claims as JWSTransactionPayload")
	}

	return payload, nil
}
