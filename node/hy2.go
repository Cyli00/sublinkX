package node

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type HY2 struct {
	Password     string
	Host         string
	Port         int
	Insecure     int
	Peer         string
	Auth         string
	UpMbps       int
	DownMbps     int
	ALPN         []string
	Name         string
	Sni          string
	Obfs         string
	ObfsPassword string
	Fingerprint  string
	Ports        string
}

// 开发者测试 CallHy 调用
func CallHy2() {
	hy2 := HY2{
		Password: "asdasd",
		Host:     "qq.com",
		Port:     11926,
		Insecure: 1,
		Peer:     "youku.com",
		Auth:     "",
		UpMbps:   11,
		DownMbps: 55,
		// ALPN:     "h3",
	}
	fmt.Println(EncodeHY2URL(hy2))
}

// hy2 编码
func EncodeHY2URL(hy2 HY2) string {
	// 如果没有设置 Name，则使用 Host:Port 作为 Fragment
	if hy2.Name == "" {
		hy2.Name = fmt.Sprintf("%s:%d", hy2.Host, hy2.Port)
	}
	u := url.URL{
		Scheme:   "hy2",
		User:     url.User(hy2.Password),
		Host:     fmt.Sprintf("%s:%d", hy2.Host, hy2.Port),
		Fragment: hy2.Name,
	}
	q := u.Query()
	q.Set("insecure", strconv.Itoa(hy2.Insecure))
	q.Set("peer", hy2.Peer)
	q.Set("auth", hy2.Auth)
	q.Set("upmbps", strconv.Itoa(hy2.UpMbps))
	q.Set("downmbps", strconv.Itoa(hy2.DownMbps))
	// q.Set("alpn", hy2.ALPN)
	// 检查query是否有空值，有的话删除
	for k, v := range q {
		if v[0] == "" {
			delete(q, k)
			// fmt.Printf("k: %v, v: %v\n", k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// hy2 解码
func DecodeHY2URL(s string) (HY2, error) {
	link := strings.TrimSpace(s)
	u, err := url.Parse(link)
	if err != nil {
		return HY2{}, fmt.Errorf("解析失败的URL: %s,错误:%s", s, err)
	}
	if !strings.EqualFold(u.Scheme, "hy2") && !strings.EqualFold(u.Scheme, "hysteria2") {
		return HY2{}, fmt.Errorf("非hy2协议: %s", s)
	}
	var password string
	var username string
	if u.User != nil {
		username = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			password = pass
		} else {
			password = username
			username = ""
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
	peer := QueryGetIgnoreCase(query, "peer")
	sni := QueryGetIgnoreCase(query, "sni")
	if sni == "" {
		sni = peer
	}
	insecure := 0
	if rawInsecure := QueryGetIgnoreCase(query, "insecure"); rawInsecure != "" {
		if parsed, err := strconv.ParseBool(rawInsecure); err == nil {
			if parsed {
				insecure = 1
			}
		}
	}
	auth := QueryGetIgnoreCase(query, "auth")
	upMbps := parseHy2Bandwidth(QueryGetIgnoreCase(query, "up"))
	if upMbps == 0 {
		upMbps = parseHy2Bandwidth(QueryGetIgnoreCase(query, "upmbps"))
	}
	downMbps := parseHy2Bandwidth(QueryGetIgnoreCase(query, "down"))
	if downMbps == 0 {
		downMbps = parseHy2Bandwidth(QueryGetIgnoreCase(query, "downmbps"))
	}
	alpn := parseHy2Alpn(QueryGetIgnoreCase(query, "alpn"))
	obfs := QueryGetIgnoreCase(query, "obfs")
	obfsPassword := QueryGetIgnoreCase(query, "obfs-password")
	if obfsPassword == "" {
		obfsPassword = QueryGetIgnoreCase(query, "obfs_password")
	}
	fingerprint := QueryGetIgnoreCase(query, "pinsha256")
	if fingerprint == "" {
		fingerprint = QueryGetIgnoreCase(query, "pinhash")
	}
	ports := QueryGetIgnoreCaseAny(query, "ports", "port-range")
	name := strings.TrimSpace(u.Fragment)
	// 如果没有设置 Name，则使用 Host:Port 作为 Fragment
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}
	if CheckEnvironment() {
		fmt.Println("username:", username)
		fmt.Println("password:", password)
		fmt.Println("server:", server)
		fmt.Println("port:", port)
		fmt.Println("insecure:", insecure)
		fmt.Println("auth:", auth)
		fmt.Println("upMbps:", upMbps)
		fmt.Println("downMbps:", downMbps)
		fmt.Println("alpn:", alpn)
		fmt.Println("peer:", peer)
		fmt.Println("sni:", sni)
		fmt.Println("obfs:", obfs)
		fmt.Println("obfsPassword:", obfsPassword)
		fmt.Println("fingerprint:", fingerprint)
		fmt.Println("ports:", ports)
		fmt.Println("name:", name)
	}
	return HY2{
		Password:     password,
		Host:         server,
		Port:         port,
		Insecure:     insecure,
		Peer:         peer,
		Auth:         auth,
		UpMbps:       upMbps,
		DownMbps:     downMbps,
		ALPN:         alpn,
		Name:         name,
		Sni:          sni,
		Obfs:         obfs,
		ObfsPassword: obfsPassword,
		Fingerprint:  fingerprint,
		Ports:        ports,
	}, nil
}

func parseHy2Alpn(raw string) []string {
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

func parseHy2Bandwidth(raw string) int {
	if raw == "" {
		return 0
	}
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimSuffix(value, "mbps")
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if v, err := strconv.Atoi(value); err == nil {
		return v
	}
	return 0
}
