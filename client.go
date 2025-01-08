package apple

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeromicro/go-zero/core/logx"
	"io"
	"net/http"
	"strings"
)

type Config struct {
	Sandbox bool   // 是否启用沙合模式 true:是
	Kid     string // 来自 App Store Connect 的私钥 ID (Ex: 2X9R4HXF34)
	//-----BEGIN PRIVATE KEY-----
	// 来自 App Store Connect 的私钥 ID 对应的私钥字符串
	//-----END PRIVATE KEY-----
	PrivateKey string // 来自 App Store Connect 的私钥 ID 对应的私钥字符串
	Iss        string // App Store Connect 中“密钥”页面中的颁发者 ID (Ex: “57246542-96fe-1a63-e053-0824d011072a")
	Bid        string // 你的应用程序的Bundle ID (Ex: “com.example.testbundleid”)
}

var BaseURL = "https://api.storekit.itunes.apple.com"
var SandboxURL = "https://api.storekit-sandbox.itunes.apple.com"

type Client struct {
	Config        *Config
	url           string // 当前操作的请求地址
	method        string // 请求方式
	payload       io.Reader
	Authorization *string
}

func convertToQueryParam(arr []int, key string) string {
	// 创建一个字符串切片，用于存储拼接后的 key=value
	var params []string
	for _, val := range arr {
		params = append(params, fmt.Sprintf("%s=%d", key, val))
	}
	// 使用 "&" 将所有 key=value 拼接成最终的查询参数字符串
	return strings.Join(params, "&")
}

// Subscriptions 查询订阅信息:
// transactionId 交易ID
// status 为状态查询参数指定多个值，以获取包含状态与任何值匹配的订阅的响应。 例如，请求返回处于活动状态的订阅（状态值为 1）和处于计费宽限期的订阅（状态值为 4）
func (c *Client) Subscriptions(transactionId string, status ...int) *Client {
	state := ""
	if len(status) > 0 {
		state = "?" + convertToQueryParam(status, "status")
	}
	c.method = "GET"
	if c.Config.Sandbox {
		c.url = fmt.Sprintf("%s/inApps/v1/subscriptions/%s%s", SandboxURL, transactionId, state)
		return c
	}
	c.url = fmt.Sprintf("%s/inApps/v1/subscriptions/%s%s", BaseURL, transactionId, state)
	return c
}

func (c *Client) Do() (*StatusResponse, error) {
	// 处理 Authorization
	if c.Authorization == nil {
		jwt, err := GenerateAuthorizationJWT(c.Config.Kid, c.Config.Bid, c.Config.Iss, c.Config.PrivateKey)
		if err != nil {
			return nil, err
		}
		c.Authorization = &jwt
	}

	logx.Debugf("method: %s, url: %s, payload: %s", c.method, c.url, c.payload)

	client := &http.Client{}
	req, err := http.NewRequest(c.method, c.url, c.payload)

	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", *c.Authorization))

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	response := &StatusResponse{}
	if err = json.Unmarshal(body, response); err != nil {
		return nil, err
	}

	return response, nil
}

func NewClient(config *Config) *Client {
	return &Client{
		Config: config,
	}
}
