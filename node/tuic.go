package node

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type Tuic struct {
	Name               string
	Password           string
	Host               string
	Port               int
	Uuid               string
	Token              string
	Congestion_control string
	Alpn               []string
	Sni                string
	Udp_relay_mode     string
	Disable_sni        bool
}

// Tuic 解码
func DecodeTuicURL(s string) (Tuic, error) {
	link := strings.TrimSpace(s)
	u, err := url.Parse(link)
	if err != nil {
		return Tuic{}, fmt.Errorf("解析失败的URL: %s", s)
	}
	if !strings.EqualFold(u.Scheme, "tuic") {
		return Tuic{}, fmt.Errorf("非tuic协议: %s", s)
	}

	var uuid, password, token string
	if u.User != nil {
		uuid = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			password = pass
		} else {
			token = uuid
			uuid = ""
		}
	}
	server := u.Hostname()
	port := 443
	if p := strings.TrimSpace(u.Port()); p != "" {
		if parsedPort, err := strconv.Atoi(p); err == nil {
			port = parsedPort
		}
	}
	query := u.Query()
	Congestioncontrol := QueryGetIgnoreCaseAny(query, "congestion_control", "congestion-controller")
	alpn := parseTuicAlpn(QueryGetIgnoreCase(query, "alpn"))
	sni := QueryGetIgnoreCase(query, "sni")
	Udprelay_mode := QueryGetIgnoreCaseAny(query, "udp_relay_mode", "udp-relay-mode")
	Disablesni := parseTuicDisableSNI(QueryGetIgnoreCaseAny(query, "disable_sni", "disable-sni"))
	name := strings.TrimSpace(u.Fragment)
	// 如果没有设置 Name，则使用 Host:Port 作为 Fragment
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}
	if CheckEnvironment() {
		fmt.Println("password:", password)
		fmt.Println("token:", token)
		fmt.Println("uuid:", uuid)
		fmt.Println("server:", server)
		fmt.Println("port:", port)
		fmt.Println("insecure:", Congestioncontrol)
		fmt.Println("Udprelay_mode:", Udprelay_mode)
		fmt.Println("alpn:", alpn)
		fmt.Println("sni:", sni)
		fmt.Println("Disablesni:", Disablesni)
		fmt.Println("name:", name)
	}
	return Tuic{
		Name:               name,
		Password:           password,
		Host:               server,
		Port:               port,
		Uuid:               uuid,
		Token:              token,
		Congestion_control: Congestioncontrol,
		Alpn:               alpn,
		Sni:                sni,
		Udp_relay_mode:     Udprelay_mode,
		Disable_sni:        Disablesni,
	}, nil
}

func parseTuicAlpn(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseTuicDisableSNI(raw string) bool {
	if raw == "" {
		return false
	}
	parsed, err := strconv.ParseBool(raw)
	if err == nil {
		return parsed
	}
	return raw == "1"
}
