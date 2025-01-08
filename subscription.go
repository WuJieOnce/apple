package apple

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type LastTransactionsItem struct {
	OriginalTransactionId string `json:"originalTransactionId"` // The original transaction identifier of the auto-renewable subscription.
	Status                string `json:"status"`                // The status of the auto-renewable subscription.
	SignedRenewalInfo     string `json:"signedRenewalInfo"`     // The subscription renewal information signed by the App Store, in JSON Web Signature (JWS) format.
	SignedTransactionInfo string `json:"signedTransactionInfo"` // The transaction information signed by the App Store, in JWS format.
}

type SubscriptionGroupIdentifierItem struct {
	SubscriptionGroupIdentifier string                `json:"subscriptionGroupIdentifier"` // The subscription group identifier of the auto-renewable subscriptions in the lastTransactions array.
	LastTransactions            *LastTransactionsItem `json:"lastTransactions"`            // An array of the most recent App Store-signed transaction information and App Store-signed renewal information for all auto-renewable subscriptions in the subscription group.
}

type StatusResponse struct {
	Data        []*SubscriptionGroupIdentifierItem `json:"data"`        // An array of information for auto-renewable subscriptions, including App Store-signed transaction information and App Store-signed renewal information.
	Environment string                             `json:"environment"` // The server environment, sandbox or production, in which the App Store generated the response.
	AppAppleId  string                             `json:"appAppleId"`  // Your app’s App Store identifier.
	BundleId    string                             `json:"bundleId"`    // Your app’s bundle identifier.
}

// SubscriptionInfo represents the response structure for Apple Subscription API
type SubscriptionInfo struct {
	Environment            string  `json:"environment"`                 // Indicates whether the transaction is in the sandbox or production environment.
	AppAppleID             int64   `json:"appAppleId"`                  // The unique identifier of the app.
	BundleID               string  `json:"bundleId"`                    // The bundle identifier of the app.
	ProductID              string  `json:"productId"`                   // The identifier of the product purchased.
	Storefront             string  `json:"storefront"`                  // The country or region associated with the App Store storefront.
	StorefrontID           string  `json:"storefrontId"`                // A unique identifier for the App Store storefront.
	OriginalTransactionID  string  `json:"originalTransactionId"`       // The original transaction identifier of the subscription.
	SubscriptionGroupID    string  `json:"subscriptionGroupIdentifier"` // The subscription group identifier for the subscription.
	PurchaseDate           string  `json:"purchaseDate"`                // The date and time the subscription was purchased.
	OriginalPurchaseDate   string  `json:"originalPurchaseDate"`        // The date and time the original transaction was purchased.
	ExpirationDate         string  `json:"expirationDate"`              // The expiration date of the subscription.
	IsInBillingRetryPeriod *bool   `json:"isInBillingRetryPeriod"`      // Indicates whether the subscription is in a billing retry state.
	GracePeriodExpiresDate *string `json:"gracePeriodExpiresDate"`      // The expiration date of the grace period, if applicable.
	AutoRenewStatus        int     `json:"autoRenewStatus"`             // The current renewal status for the subscription.
	AutoRenewProductID     *string `json:"autoRenewProductId"`          // The product ID for the next renewal.
	IsUpgraded             *bool   `json:"isUpgraded"`                  // Indicates whether the subscription has been upgraded.
	OfferType              *int    `json:"offerType"`                   // The type of offer used for the subscription purchase, if applicable.
	OfferIdentifier        *string `json:"offerIdentifier"`             // The identifier of the subscription offer, if applicable.
	SignedTransactionInfo  string  `json:"signedTransactionInfo"`       // The signed transaction information.
	SignedRenewalInfo      string  `json:"signedRenewalInfo"`           // The signed renewal information.
}

// parseJWT parses the signed JWT string and returns the claims.
func (s *SubscriptionInfo) parseJWT(signedJWT string) (jwt.MapClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(signedJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse JWT claims")
	}

	return claims, nil
}

func (s *SubscriptionInfo) GetExpirationTime() (*jwt.NumericDate, error) {
	claims, err := s.parseJWT(s.SignedTransactionInfo)
	if err != nil {
		return nil, err
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("expiration time (exp) not found in claims")
	}

	return jwt.NewNumericDate(time.Unix(int64(exp), 0)), nil
}

func (s *SubscriptionInfo) GetIssuedAt() (*jwt.NumericDate, error) {
	claims, err := s.parseJWT(s.SignedTransactionInfo)
	if err != nil {
		return nil, err
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, errors.New("issued at (iat) not found in claims")
	}

	return jwt.NewNumericDate(time.Unix(int64(iat), 0)), nil
}

func (s *SubscriptionInfo) GetNotBefore() (*jwt.NumericDate, error) {
	claims, err := s.parseJWT(s.SignedTransactionInfo)
	if err != nil {
		return nil, err
	}

	nbf, ok := claims["nbf"].(float64)
	if !ok {
		return nil, errors.New("not before (nbf) not found in claims")
	}

	return jwt.NewNumericDate(time.Unix(int64(nbf), 0)), nil
}

func (s *SubscriptionInfo) GetIssuer() (string, error) {
	claims, err := s.parseJWT(s.SignedTransactionInfo)
	if err != nil {
		return "", err
	}

	iss, ok := claims["iss"].(string)
	if !ok {
		return "", errors.New("issuer (iss) not found in claims")
	}

	return iss, nil
}

func (s *SubscriptionInfo) GetSubject() (string, error) {
	claims, err := s.parseJWT(s.SignedTransactionInfo)
	if err != nil {
		return "", err
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("subject (sub) not found in claims")
	}

	return sub, nil
}

func (s *SubscriptionInfo) GetAudience() (jwt.ClaimStrings, error) {
	claims, err := s.parseJWT(s.SignedTransactionInfo)
	if err != nil {
		return nil, err
	}

	aud, ok := claims["aud"].([]interface{})
	if !ok {
		return nil, errors.New("audience (aud) not found in claims")
	}

	// Convert the audience to jwt.ClaimStrings
	audience := make(jwt.ClaimStrings, len(aud))
	for i, v := range aud {
		audience[i], ok = v.(string)
		if !ok {
			return nil, errors.New("invalid audience type in claims")
		}
	}

	return audience, nil
}
