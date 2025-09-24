package node

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type SqlConfig struct {
	Clash string `json:"clash"`
	Surge string `json:"surge"`
	Udp   bool   `json:"udp"`
	Cert  bool   `json:"cert"`
}

// ipv6地址匹配规则
func ValRetIPv6Addr(s string) string {
	pattern := `\[([0-9a-fA-F:]+)\]`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(s)
	if len(match) > 0 {
		return match[1]
	} else {
		return s
	}
}

// 判断是否需要补全
func IsBase64makeup(s string) string {
	l := len(s)
	if l%4 != 0 {
		return s + strings.Repeat("=", 4-l%4)
	}
	return s
}

// base64编码
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// base64解码
func Base64Decode(s string) string {
	// 去除空格
	s = strings.ReplaceAll(s, " ", "")
	// 判断是否有特殊字符来判断是标准base64还是url base64
	match, err := regexp.MatchString(`[_-]`, s)
	if err != nil {
		fmt.Println(err)
	}
	if !match {
		// 默认使用标准解码
		encoded := IsBase64makeup(s)
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return s // 返回原字符串
		}
		decoded_str := string(decoded)
		return decoded_str

	} else {
		// 如果有特殊字符则使用URL解码
		encoded := IsBase64makeup(s)
		decoded, err := base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return s // 返回原字符串
		}
		decoded_str := string(decoded)
		return decoded_str
	}
}

// base64解码不自动补齐
func Base64Decode2(s string) string {
	// 去除空格
	s = strings.ReplaceAll(s, " ", "")
	// 判断是否有特殊字符来判断是标准base64还是url base64
	match, err := regexp.MatchString(`[_-]`, s)
	if err != nil {
		fmt.Println(err)
	}
	if !match {
		// 默认使用标准解码
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return s // 返回原字符串
		}
		decoded_str := string(decoded)
		return decoded_str

	} else {
		// 如果有特殊字符则使用URL解码
		decoded, err := base64.URLEncoding.DecodeString(s)
		if err != nil {
			return s // 返回原字符串
		}
		decoded_str := string(decoded)
		return decoded_str
	}
}

// QueryGetIgnoreCase returns the first value for key regardless of original casing.
func QueryGetIgnoreCase(values url.Values, key string) string {
	if len(values) == 0 {
		return ""
	}
	for k, v := range values {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}

// QueryGetIgnoreCaseAny 允许按多个候选键（含连字符/下划线）匹配查询参数。
func QueryGetIgnoreCaseAny(values url.Values, keys ...string) string {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if val := QueryGetIgnoreCase(values, key); val != "" {
			return val
		}
		alt := key
		if strings.Contains(key, "-") {
			alt = strings.ReplaceAll(key, "-", "_")
		} else if strings.Contains(key, "_") {
			alt = strings.ReplaceAll(key, "_", "-")
		}
		if alt != key {
			if val := QueryGetIgnoreCase(values, alt); val != "" {
				return val
			}
		}
	}
	return ""
}

// ShouldEnableUDP inspects the raw URI and returns the desired UDP flag.
// If the uri lacks an udp query parameter, the defaultVal is returned.
func ShouldEnableUDP(rawURL string, defaultVal bool) bool {
	if rawURL == "" {
		return defaultVal
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return defaultVal
	}
	values := u.Query()
	for key, v := range values {
		if !strings.EqualFold(key, "udp") || len(v) == 0 {
			continue
		}
		parsed, err := strconv.ParseBool(strings.TrimSpace(v[0]))
		if err != nil {
			return defaultVal
		}
		return parsed
	}
	return defaultVal
}

// 检查环境
func CheckEnvironment() bool {
	APP_ENV := os.Getenv("APP_ENV")
	if APP_ENV == "" {
		// fmt.Println("APP_ENV环境变量未设置")
		return false
	}
	if strings.Contains(APP_ENV, "development") {
		// fmt.Println("你现在是开发环境")
		return true
	}
	// fmt.Println("你现在是生产环境")
	return false
}
