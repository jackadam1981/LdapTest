//go:build linux || darwin || windows
// +build linux darwin windows

package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"image/color"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// myTheme 自定义主题结构体，继承fyne.Theme接口
type myTheme struct {
	fyne.Theme
}

// Color 自定义颜色方案
// 参数：
//
//	name - 颜色名称（如禁用状态颜色）
//	variant - 主题变体（亮色/暗色模式）
//
// 返回值：color.Color - 对应的颜色值
func (m myTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// 修改禁用状态文字颜色为纯黑色
	if name == theme.ColorNameDisabled {
		return &color.NRGBA{R: 0, G: 0, B: 0, A: 255} // RGBA(0,0,0,255)
	}
	// 其他颜色使用默认主题设置
	return theme.DefaultTheme().Color(name, variant)
}

// Font 获取字体资源（保持默认）
func (m myTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon 获取图标资源（保持默认）
func (m myTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size 获取尺寸设置（保持默认）
func (m myTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

// CustomDomainEntry 自定义域名输入框组件
// 继承自widget.Entry，添加焦点丢失回调功能
type CustomDomainEntry struct {
	widget.Entry
	onFocusLost func() // 焦点丢失时的回调函数
}

// NewCustomDomainEntry 构造函数
// 参数：onFocusLost - 焦点丢失时的回调函数
func NewCustomDomainEntry(onFocusLost func()) *CustomDomainEntry {
	entry := &CustomDomainEntry{onFocusLost: onFocusLost}
	entry.ExtendBaseWidget(entry) // 必须调用以实现自定义组件
	return entry
}

// FocusLost 重写焦点丢失事件处理
func (e *CustomDomainEntry) FocusLost() {
	e.Entry.FocusLost() // 调用基类方法
	if e.onFocusLost != nil {
		e.onFocusLost() // 执行自定义回调
	}
}

// CustomPortEntry 自定义端口输入框组件
// 继承自widget.Entry，添加获取焦点时自动填充默认值功能
type CustomPortEntry struct {
	widget.Entry
}

// NewCustomPortEntry 构造函数
func NewCustomPortEntry() *CustomPortEntry {
	entry := &CustomPortEntry{}
	entry.ExtendBaseWidget(entry)
	entry.SetText("389") // 设置初始显示值
	return entry
}

// FocusLost 重写获取焦点事件处理
func (e *CustomPortEntry) FocusLost() {
	e.Entry.FocusLost()
	if e.Text == "" {
		if isSSLEnabled {
			e.SetText("636")
		} else {
			e.SetText("389")
		}
	}
}

func (e *CustomPortEntry) FocusGained() {
	if e.Text == "" {
		if isSSLEnabled {
			e.SetText("636")
		} else {
			e.SetText("389")
		}
	}
	e.Entry.FocusGained()
}

// SetDefaultPort 设置默认端口
func (e *CustomPortEntry) SetDefaultPort(ssl bool) {
	if ssl {
		e.SetText("636")
	} else {
		e.SetText("389")
	}
}

// GetPort 获取当前端口号
func (e *CustomPortEntry) GetPort() (int, error) {
	var port int
	if _, err := fmt.Sscanf(e.Text, "%d", &port); err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("无效端口号：%s", e.Text)
	}
	return port, nil
}

// LDAPClient 结构体定义LDAP客户端配置
type LDAPClient struct {
	host         string       // LDAP服务器地址（IP或域名）
	port         int          // LDAP服务端口（默认389）
	bindDN       string       // 绑定用识别名（用于认证的Distinguished Name）
	bindPassword string       // 绑定用密码
	updateFunc   func(string) // 添加状态更新函数引用
	conn         *ldap.Conn   // LDAP连接实例
	useTLS       bool         // 是否使用TLS/SSL
}

// 全局变量
var (
	isSSLEnabled bool // SSL支持状态
)

// encodePassword 将密码编码为Active Directory所需的格式
func encodePassword(password string) string {
	quotedPassword := fmt.Sprintf("\"%s\"", password)
	encodedPassword := utf16.Encode([]rune(quotedPassword))
	bytePassword := make([]byte, len(encodedPassword)*2)
	for i, v := range encodedPassword {
		bytePassword[i*2] = byte(v)
		bytePassword[i*2+1] = byte(v >> 8)
	}
	return string(bytePassword)
}

// isPortOpen 检查LDAP服务端口是否开放
// 返回值：bool - true表示端口开放，false表示关闭
func (client *LDAPClient) isPortOpen() bool {
	address := net.JoinHostPort(client.host, fmt.Sprintf("%d", client.port))

	// 连接类型记录
	connType := "标准LDAP"
	if client.useTLS {
		connType = "SSL/TLS"
	}

	log.Printf("检查%s端口 | 服务器: %s | 端口: %d", connType, client.host, client.port)

	// 使用带3秒超时的TCP协议尝试建立连接
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		log.Printf("端口测试失败 | 错误: %v", err)
		// 区分不同类型的错误
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				log.Println("连接超时")
				if client.updateFunc != nil {
					client.updateFunc(fmt.Sprintf("%s端口 %d 连接超时", connType, client.port))
				}
			} else if netErr.Temporary() {
				log.Println("临时网络错误")
				if client.updateFunc != nil {
					client.updateFunc(fmt.Sprintf("%s端口 %d 临时网络错误", connType, client.port))
				}
			}
		}
		return false
	}

	conn.Close() // 关闭测试连接
	log.Printf("%s端口 %d 已开放", connType, client.port)
	if client.updateFunc != nil {
		client.updateFunc(fmt.Sprintf("%s端口 %d 已开放", connType, client.port))
	}
	return true
}

// getURL 根据SSL状态返回合适的LDAP URL
func (client *LDAPClient) getURL() string {
	scheme := "ldap"
	if client.useTLS {
		scheme = "ldaps"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, client.host, client.port)
}

// connect 建立LDAP连接
func (client *LDAPClient) connect() error {
	if client.conn != nil {
		// 如果已经有连接，先检查连接是否有效
		searchRequest := ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"supportedLDAPVersion"},
			nil,
		)

		_, err := client.conn.Search(searchRequest)
		if err == nil {
			// 连接仍然有效，直接返回
			return nil
		}
		// 连接无效，关闭它
		client.conn.Close()
		client.conn = nil
	}

	// 记录连接URL
	log.Printf("正在连接到 %s", client.getURL())
	if client.updateFunc != nil {
		client.updateFunc(fmt.Sprintf("正在连接到 %s", client.getURL()))
	}

	// 建立新连接
	var err error
	if client.useTLS {
		// 使用 TLS 配置
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
		}
		client.conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
	} else {
		// 使用普通 LDAP 连接
		client.conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
	}

	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	return nil
}

// bind 使用指定的凭据进行LDAP绑定
func (client *LDAPClient) bind(bindDN, bindPassword string) error {
	if client.conn == nil {
		if err := client.connect(); err != nil {
			return err
		}
	}

	if err := client.conn.Bind(bindDN, bindPassword); err != nil {
		return fmt.Errorf("绑定失败: %v", err)
	}

	return nil
}

// close 关闭LDAP连接
func (client *LDAPClient) close() {
	if client.conn != nil {
		client.conn.Close()
		client.conn = nil
	}
}

// bindWithRetry 带重试的LDAP绑定
func (client *LDAPClient) bindWithRetry(bindDN, bindPassword string) error {
	maxRetries := 3
	var lastErr error

	connType := "标准LDAP"
	if client.useTLS {
		connType = "SSL/TLS"
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("尝试%s绑定 (尝试 %d/%d) | DN: %s", connType, attempt, maxRetries, bindDN)

		// 尝试绑定
		err := client.bind(bindDN, bindPassword)
		if err == nil {
			// 绑定成功
			log.Printf("%s绑定成功 | DN: %s", connType, bindDN)
			return nil
		}

		lastErr = err
		log.Printf("%s绑定失败 (尝试 %d/%d) | 错误: %v", connType, attempt, maxRetries, err)

		// 分析错误类型
		if ldapErr, ok := err.(*ldap.Error); ok {
			// 处理特定的LDAP错误
			switch ldapErr.ResultCode {
			case ldap.LDAPResultInvalidCredentials:
				// 凭据错误，不需要重试
				log.Printf("凭据无效，停止重试 | 错误代码: %d", ldapErr.ResultCode)
				return fmt.Errorf("无效的凭据: %v", err)
			case ldap.LDAPResultInsufficientAccessRights:
				// 权限不足，不需要重试
				log.Printf("权限不足，停止重试 | 错误代码: %d", ldapErr.ResultCode)
				return fmt.Errorf("权限不足: %v", err)
			case 200: // 网络错误代码
				// 网络错误，关闭连接并重试
				log.Printf("网络错误，将重试 | 错误代码: %d", ldapErr.ResultCode)
			}
		}

		// 如果不是最后一次尝试，关闭连接并等待一段时间再重试
		if attempt < maxRetries {
			client.close()

			// 增加等待时间，实现指数退避
			waitTime := time.Duration(attempt) * 500 * time.Millisecond
			log.Printf("等待 %v 后重试...", waitTime)
			time.Sleep(waitTime)

			// 重新连接
			if err := client.connect(); err != nil {
				log.Printf("重新连接失败: %v", err)
				continue // 继续下一次尝试
			}
		}
	}

	// 所有尝试都失败了
	return fmt.Errorf("在 %d 次尝试后绑定失败: %v", maxRetries, lastErr)
}

// testLDAPService 测试LDAP服务连通性
func (client *LDAPClient) testLDAPService() bool {
	defer client.close() // 确保连接最后被关闭

	// 记录连接类型
	connectionType := "标准LDAP"
	if client.useTLS {
		connectionType = "SSL/TLS加密LDAP"
	}
	log.Printf("开始测试%s连接 | 服务器: %s | 端口: %d", connectionType, client.host, client.port)

	if client.updateFunc != nil {
		client.updateFunc(fmt.Sprintf("测试%s连接...", connectionType))
	}

	if err := client.bindWithRetry(client.bindDN, client.bindPassword); err != nil {
		log.Printf("%s服务测试失败: %v", connectionType, err)
		if client.updateFunc != nil {
			client.updateFunc(fmt.Sprintf("%s连接测试失败: %v", connectionType, err))
		}
		return false
	}

	log.Printf("%s服务验证成功", connectionType)
	if client.updateFunc != nil {
		client.updateFunc(fmt.Sprintf("%s连接测试成功", connectionType))
	}
	return true
}

// testUserAuth 测试用户认证流程
func (client *LDAPClient) testUserAuth(testUser, testPassword, searchDN, filterPattern string) bool {
	defer client.close() // 确保连接最后被关闭

	// 使用管理员凭证进行绑定
	if err := client.bindWithRetry(client.bindDN, client.bindPassword); err != nil {
		log.Printf("管理员绑定失败: %v", err)
		return false
	}

	// 使用选定的过滤器进行查询
	searchFilter := fmt.Sprintf(filterPattern, ldap.EscapeFilter(testUser))
	log.Printf("使用过滤器搜索: %s", searchFilter)

	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		[]string{"dn"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		log.Printf("搜索失败: %v", err)
		return false
	}

	if len(sr.Entries) != 1 {
		log.Printf("用户搜索结果数量异常: %d", len(sr.Entries))
		return false
	}

	userDN := sr.Entries[0].DN
	log.Printf("找到用户DN: %s", userDN)

	// 尝试使用用户凭证绑定
	if err := client.bindWithRetry(userDN, testPassword); err != nil {
		log.Printf("用户绑定失败: %v", err)
		return false
	}

	log.Printf("用户认证成功")
	return true
}

// extractUsernameFromDN 从DN中提取用户名
func extractUsernameFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
}

// searchUserInDomain 在整个域中搜索用户
func (client *LDAPClient) searchUserInDomain(username string) (bool, string) {
	var l *ldap.Conn
	var err error

	if client.useTLS {
		// 使用 TLS 配置
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
		}
		l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
	} else {
		// 使用普通 LDAP 连接
		l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
	}

	if err != nil {
		log.Println("连接失败:", err)
		return false, ""
	}
	defer l.Close()

	// 使用管理员凭证进行绑定
	if err := l.Bind(client.bindDN, client.bindPassword); err != nil {
		log.Println("管理员绑定失败:", err)
		return false, ""
	}

	// 使用自动生成的域DN作为搜索基准
	domainParts := strings.Split(client.host, ".")
	var baseDN string
	for _, part := range domainParts {
		baseDN += "dc=" + part + ","
	}
	baseDN = strings.TrimSuffix(baseDN, ",")

	// 构建符合AD查询的过滤器
	searchFilter := fmt.Sprintf("(&(objectClass=user)(name=%s*))", username)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter, // 使用新的过滤器
		[]string{"distinguishedName"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Printf("搜索失败 (基准DN: %s): %v", baseDN, err) // 添加详细日志
		return false, ""
	}

	// 允许返回多个结果时选择第一个
	if len(sr.Entries) > 0 {
		return true, sr.Entries[0].DN
	}
	return false, ""
}

// 添加常用LDAP过滤器结构
type LDAPFilter struct {
	name    string // 过滤器名称
	pattern string // 过滤器模式
}

// 定义常用的LDAP过滤器
var commonFilters = []LDAPFilter{
	{
		name:    "使用sAMAccountName搜索（登录名）",
		pattern: "(&(objectClass=user)(sAMAccountName=%s))",
	},
	{
		name:    "使用userPrincipalName搜索（邮箱格式）",
		pattern: "(&(objectClass=user)(userPrincipalName=%s))",
	},
	{
		name:    "使用mail搜索（邮箱地址）",
		pattern: "(&(objectClass=user)(mail=%s))",
	},
	{
		name:    "使用uid搜索（OpenLDAP默认）",
		pattern: "(&(objectClass=user)(uid=%s))",
	},
	{
		name:    "使用cn搜索（通用名称）",
		pattern: "(&(objectClass=user)(cn=%s))",
	},
}

// ensureDNExists 递归检查/创建目标DN路径
func (client *LDAPClient) ensureDNExists(targetDN string) error {
	defer client.close() // 确保连接最后被关闭

	if err := client.bindWithRetry(client.bindDN, client.bindPassword); err != nil {
		return fmt.Errorf("管理员绑定失败: %v", err)
	}

	// 反向解析DN层级（从叶子节点到根节点）
	parts := strings.Split(targetDN, ",")
	var currentDN string

	// 从根节点开始构建和检查路径
	for i := len(parts) - 1; i >= 0; i-- {
		if i == len(parts)-1 {
			currentDN = parts[i]
		} else {
			currentDN = parts[i] + "," + currentDN
		}

		// 检查当前DN是否存在
		searchRequest := ldap.NewSearchRequest(
			currentDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"objectClass"},
			nil,
		)

		_, err := client.conn.Search(searchRequest)
		if err != nil {
			// 如果搜索失败，尝试创建该层级
			var addRequest *ldap.AddRequest

			if strings.HasPrefix(parts[i], "CN=") {
				name := strings.TrimPrefix(parts[i], "CN=")
				addRequest = ldap.NewAddRequest(currentDN, nil)
				addRequest.Attribute("objectClass", []string{"top", "container"})
				addRequest.Attribute("cn", []string{name})
				addRequest.Attribute("showInAdvancedViewOnly", []string{"FALSE"})
				addRequest.Attribute("description", []string{"自动创建的容器"})
				client.updateFunc(fmt.Sprintf("正在创建容器: %s", currentDN))
			} else if strings.HasPrefix(parts[i], "OU=") {
				name := strings.TrimPrefix(parts[i], "OU=")
				addRequest = ldap.NewAddRequest(currentDN, nil)
				addRequest.Attribute("objectClass", []string{"top", "organizationalUnit"})
				addRequest.Attribute("ou", []string{name})
				addRequest.Attribute("name", []string{name})
				addRequest.Attribute("displayName", []string{name})
				addRequest.Attribute("description", []string{"自动创建的组织单位"})
				addRequest.Attribute("showInAdvancedViewOnly", []string{"FALSE"})
				// 添加 managedBy 属性（可选，指定 OU 的管理者）
				if client.bindDN != "" {
					addRequest.Attribute("managedBy", []string{client.bindDN})
				}
				client.updateFunc(fmt.Sprintf("正在创建组织单位: %s", currentDN))
			} else if strings.HasPrefix(parts[i], "DC=") {
				// 跳过 DC 组件，因为它们应该已经存在
				continue
			}

			if addRequest != nil {
				err = client.conn.Add(addRequest)
				if err != nil {
					// 忽略"已存在"错误
					if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultEntryAlreadyExists {
						client.updateFunc(fmt.Sprintf("容器已存在: %s", currentDN))
						continue
					}
					return fmt.Errorf("创建容器失败 %s: %v", currentDN, err)
				}
				client.updateFunc(fmt.Sprintf("成功创建: %s", currentDN))
			}
		}
	}

	return nil
}

// moveUser 执行用户移动操作
func (client *LDAPClient) moveUser(oldDN, newDN string) error {
	defer client.close() // 确保连接最后被关闭

	log.Printf("开始移动操作 | 源: %s -> 目标: %s", oldDN, newDN)

	if err := client.bindWithRetry(client.bindDN, client.bindPassword); err != nil {
		return fmt.Errorf("管理员绑定失败: %v", err)
	}

	// 解析新DN的RDN和上级DN
	newRDNParts := strings.SplitN(newDN, ",", 2)
	if len(newRDNParts) != 2 {
		return fmt.Errorf("无效的新DN格式，示例: CN=NewName,OU=容器")
	}
	newRDN := newRDNParts[0]
	newSuperior := newRDNParts[1]

	// 创建ModifyDN请求前检查目标容器是否存在
	if err := client.ensureDNExists(newSuperior); err != nil {
		return fmt.Errorf("目标容器验证失败: %v", err)
	}

	modifyDNRequest := ldap.NewModifyDNRequest(
		oldDN,
		newRDN,
		true, // 删除旧RDN
		newSuperior,
	)

	// 添加ModifyDN请求详情日志
	log.Printf("执行ModifyDN请求 | 旧RDN: %s | 新RDN: %s | 新上级: %s",
		oldDN, newRDN, newSuperior)

	if err := client.conn.ModifyDN(modifyDNRequest); err != nil {
		log.Printf("ModifyDN操作失败 | 错误类型: %T | 详细错误: %+v", err, err)
		if ldapErr, ok := err.(*ldap.Error); ok {
			log.Printf("LDAP错误详情 | 代码: %d | 消息: %s | 匹配的DN: %s",
				ldapErr.ResultCode, ldapErr.Err.Error(), ldapErr.MatchedDN)
		}
		return fmt.Errorf("移动操作失败: %v", err)
	}

	log.Printf("移动操作完成 | 新完整DN: %s", newDN)
	return nil
}

func createUserWithoutSSL(l *ldap.Conn, userDN string, userName string, host string, updateFunc func(string)) error {
	log.Printf("非SSL模式创建账户: %s", userDN)

	// 创建用户请求
	addRequest := ldap.NewAddRequest(userDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("sAMAccountName", []string{userName})
	addRequest.Attribute("userAccountControl", []string{"2"}) // 禁用账户 (ACCOUNTDISABLE)

	// 添加必需的属性
	addRequest.Attribute("givenName", []string{userName})
	addRequest.Attribute("sn", []string{userName})
	addRequest.Attribute("displayName", []string{userName})
	addRequest.Attribute("name", []string{userName})
	addRequest.Attribute("userPrincipalName", []string{fmt.Sprintf("%s@%s", userName, host)})

	// 执行创建
	if err := l.Add(addRequest); err != nil {
		log.Printf("创建用户失败: %v", err)
		return fmt.Errorf("创建用户失败: %v", err)
	}

	log.Printf("非SSL模式成功创建禁用账户: %s", userDN)
	updateFunc(fmt.Sprintf("成功创建新用户: %s（账户已禁用）", userDN))
	return nil
}

func createUserWithSSL(l *ldap.Conn, client *LDAPClient, userDN string, userName string, password string, host string, myWindow fyne.Window, updateFunc func(string)) error {
	log.Printf("SSL模式创建账户: %s", userDN)
	updateFunc(fmt.Sprintf("正在创建SSL模式账户: %s", userDN))

	// 检查用户是否已存在
	baseDN := strings.Join(strings.Split(userDN, ",")[1:], ",") // 基础DN
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", userName),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Printf("检查用户是否存在时出错: %v", err)
		return fmt.Errorf("检查用户是否存在时出错: %v", err)
	}

	if len(sr.Entries) > 0 {
		message := fmt.Sprintf("用户 %s 已存在，跳过创建", userName)
		log.Printf(message)
		updateFunc(message)
		return nil
	}

	// 确保父容器存在
	log.Printf("验证父容器 %s 是否存在", baseDN)
	updateFunc(fmt.Sprintf("验证父容器 %s 是否存在", baseDN))
	if err := client.ensureDNExists(baseDN); err != nil {
		log.Printf("父容器不存在或无法访问: %v", err)
		return fmt.Errorf("父容器不存在或无法访问: %v", err)
	}

	// 准备密码
	log.Printf("准备加密密码...")
	updateFunc("准备加密密码...")
	unicodePwd := encodePassword(password)

	// 准备用户属性
	log.Printf("准备用户属性...")
	updateFunc("准备用户属性...")

	// 创建用户请求
	addRequest := ldap.NewAddRequest(userDN, nil)

	// 必需的基本属性
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("cn", []string{userName})
	addRequest.Attribute("sAMAccountName", []string{userName})

	// 使用与PowerShell脚本相同的userAccountControl值
	// 512 = NORMAL_ACCOUNT
	addRequest.Attribute("userAccountControl", []string{"512"})

	// 其他推荐属性
	addRequest.Attribute("name", []string{userName})
	addRequest.Attribute("displayName", []string{userName})
	addRequest.Attribute("givenName", []string{userName})
	addRequest.Attribute("sn", []string{userName})

	// 设置UPN - 确保使用正确的域名
	domain := host
	if !strings.Contains(domain, ".") {
		// 尝试从baseDN提取域名
		domainComponents := []string{}
		for _, part := range strings.Split(baseDN, ",") {
			if strings.HasPrefix(part, "DC=") {
				dc := strings.TrimPrefix(part, "DC=")
				domainComponents = append(domainComponents, dc)
			}
		}
		if len(domainComponents) > 0 {
			domain = strings.Join(domainComponents, ".")
		}
	}

	addRequest.Attribute("userPrincipalName", []string{fmt.Sprintf("%s@%s", userName, domain)})

	// 在创建时直接设置密码
	addRequest.Attribute("unicodePwd", []string{unicodePwd})

	// 记录所有要添加的属性
	log.Printf("用户DN: %s", userDN)
	log.Printf("添加以下属性:")
	for _, attr := range addRequest.Attributes {
		attrValue := attr.Vals
		// 如果是密码，不要在日志中显示
		if attr.Type == "unicodePwd" {
			attrValue = []string{"[受保护的密码]"}
		}
		log.Printf("  - %s: %v", attr.Type, attrValue)
	}

	// 执行创建
	log.Printf("正在创建用户...")
	updateFunc("正在创建用户...")
	if err := l.Add(addRequest); err != nil {
		errMsg := fmt.Sprintf("创建用户失败: %v", err)
		log.Printf(errMsg)

		// 获取更详细的错误信息
		if ldapErr, ok := err.(*ldap.Error); ok {
			log.Printf("LDAP错误代码: %d", ldapErr.ResultCode)

			// 特殊处理错误代码53 (Unwilling To Perform)
			if ldapErr.ResultCode == 53 {
				log.Printf("可能的原因: 密码不满足复杂性要求，或缺少必需属性")
				updateFunc("错误: 创建用户失败。可能的原因: 密码不满足复杂性要求，或缺少必需属性")

				// 提示用户调整密码
				dialog.ShowInformation("密码策略", "创建用户失败，可能是因为密码不满足复杂性要求。请尝试使用包含大小写字母、数字和特殊字符的密码。", myWindow)
				return fmt.Errorf("创建用户失败: 密码可能不满足复杂性要求")
			}
		}

		updateFunc(errMsg)
		return fmt.Errorf(errMsg)
	}

	successMsg := fmt.Sprintf("SSL模式成功创建启用账户: %s (密码已设置)", userDN)
	log.Printf(successMsg)
	updateFunc(successMsg)
	return nil
}

func main() {
	// 设置中文字体路径（仅Windows系统）
	os.Setenv("FYNE_FONT", "C:\\Windows\\Fonts\\SIMYOU.TTF")

	// 创建应用程序实例
	myApp := app.New()
	// 应用自定义主题
	myApp.Settings().SetTheme(&myTheme{})
	// 创建主窗口
	myWindow := myApp.NewWindow("LDAP Client")

	// 创建管理员DN输入框
	adminEntry := widget.NewEntry()
	adminEntry.SetPlaceHolder("请输入管理员DN")

	// 创建搜索DN输入框（用于用户搜索的基准DN）
	searchDNEntry := widget.NewEntry()
	searchDNEntry.SetPlaceHolder("请输入搜索DN")
	searchDNEntry.SetText("CN=Users,DC=example,DC=com") // 默认示例值

	// 创建LDAP DN输入框（用于创建LDAP账号）
	ldapDNEntry := widget.NewEntry()
	ldapDNEntry.SetPlaceHolder("请输入LDAP DN")

	// 创建LDAP权限组输入框（既可以输入又可以选择）
	ldapGroupEntry := widget.NewSelectEntry([]string{""})
	ldapGroupEntry.SetPlaceHolder("请输入或选择权限组")

	// 创建自定义域名输入框（带自动生成DN功能）
	var domainEntry *CustomDomainEntry
	domainEntry = NewCustomDomainEntry(func() {
		domainParts := strings.Split(domainEntry.Text, ".")
		var dnParts []string
		for _, part := range domainParts {
			dnParts = append(dnParts, "DC="+part)
		}
		domainDN := strings.Join(dnParts, ",")

		// 自动生成管理员DN和搜索DN
		adminEntry.SetText("CN=Administrator,CN=Users," + domainDN)
		searchDNEntry.SetText(domainDN)
		ldapDNEntry.SetText("CN=Ldap,CN=Ldap," + domainDN)

		// 修改组默认路径为CN=Builtin
		ldapGroupEntry.SetText("CN=LDAP Connection,CN=Users," + domainDN)
	})

	// 设置默认域名和提示文本
	domainEntry.SetText("example.com")
	domainEntry.SetPlaceHolder("请输入LDAP服务器地址，一般是根域名")

	// 创建自定义端口输入框（带验证）
	portEntry := NewCustomPortEntry()
	portEntry.SetPlaceHolder("请输入LDAP端口 (1-65535)")

	// 创建密码输入框
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("请输入管理员密码")

	// 创建LDAP密码输入框
	ldappasswordEntry := widget.NewPasswordEntry()
	ldappasswordEntry.SetPlaceHolder("请输入LDAP密码")

	// Create the status area first
	statusArea := widget.NewMultiLineEntry()
	statusArea.Disable()                    // 设置为只读模式
	statusArea.Wrapping = fyne.TextWrapWord // 启用自动换行

	// Define the updateStatus function after statusArea is defined
	updateStatus := func(status string) {
		currentTime := time.Now().Format("15:04:05")      // 获取当前时间
		statusArea.TextStyle = fyne.TextStyle{Bold: true} // 设置粗体显示
		newText := statusArea.Text + currentTime + " " + status + "\n"
		statusArea.SetText(newText)
		statusArea.CursorRow = len(strings.Split(statusArea.Text, "\n")) - 1 // 自动滚动到底部
	}

	// Now create the groupButton using the updateStatus function
	groupButton := widget.NewButton("检查权限组", func() {
		// 在创建client实例前添加端口解析逻辑
		var port int
		if _, err := fmt.Sscanf(portEntry.Text, "%d", &port); err != nil {
			updateStatus("无效的端口号")
			return
		}

		// 创建 LDAP 客户端实例
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       adminEntry.Text,
			bindPassword: passwordEntry.Text,
			updateFunc:   updateStatus,
			useTLS:       isSSLEnabled,
		}

		// 先检查端口连通性
		if !client.isPortOpen() {
			updateStatus(fmt.Sprintf("端口 %d 未开放", port))
			return
		}

		// 验证管理员凭证
		if !client.testLDAPService() {
			dialog.ShowError(fmt.Errorf("管理员认证失败\n可能原因：\n1. 密码错误\n2. DN格式错误\n3. 权限不足"), myWindow)
			updateStatus("管理员凭证验证失败")
			return
		}

		// 从输入的组DN中提取CN
		enteredGroupCN := strings.SplitN(ldapGroupEntry.Text, ",", 2)[0]
		if !strings.HasPrefix(enteredGroupCN, "CN=") {
			updateStatus("无效的组DN格式")
			return
		}
		groupName := strings.TrimPrefix(enteredGroupCN, "CN=")

		// 修改搜索请求为按CN查询
		searchRequest := ldap.NewSearchRequest(
			searchDNEntry.Text,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName)),
			[]string{"dn"},
			nil,
		)

		log.Println("尝试连接到 LDAP 服务器...")
		var l *ldap.Conn
		var connErr error

		if client.useTLS {
			// 使用 TLS 配置
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
			}
			l, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
		} else {
			// 使用普通 LDAP 连接
			l, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
		}

		if connErr != nil {
			updateStatus(fmt.Sprintf("连接失败: %v", connErr))
			log.Printf("连接失败: %v", connErr)
			if netErr, ok := connErr.(net.Error); ok {
				if netErr.Timeout() {
					log.Println("连接超时")
				}
				if netErr.Temporary() {
					log.Println("临时网络错误")
				}
			}
			log.Printf("详细错误信息: %T - %v", connErr, connErr)
			return
		}
		log.Println("连接到 LDAP 服务器成功")
		defer l.Close()

		log.Println("尝试绑定到 LDAP 服务器...")
		if err := l.Bind(client.bindDN, client.bindPassword); err != nil {
			updateStatus(fmt.Sprintf("绑定失败: %v", err))
			log.Printf("绑定失败: %v", err)
			return
		}
		log.Println("绑定到 LDAP 服务器成功")

		log.Println("执行搜索请求...")
		sr, err := l.Search(searchRequest)
		if err != nil {
			updateStatus(fmt.Sprintf("搜索失败: %v", err))
			return
		}

		// 检查是否存在同名组
		if len(sr.Entries) > 0 {
			foundGroupDN := sr.Entries[0].DN

			// 当DN完全相同时（不区分大小写）
			if strings.EqualFold(strings.ToLower(foundGroupDN), strings.ToLower(ldapGroupEntry.Text)) {
				// 提示是否需要重新授权
				dialog.ShowConfirm("组已存在",
					fmt.Sprintf("组已存在且位置正确：\n%s\n\n是否要重新授权该组？", foundGroupDN),
					func(reauth bool) {
						if reauth {
							updateStatus("开始重新授权组权限...")

							// 检查连接状态
							if l == nil {
								log.Println("LDAP连接为空，尝试重新建立连接...")

								if client.useTLS {
									// 使用 TLS 配置
									tlsConfig := &tls.Config{
										InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
									}
									l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
								} else {
									// 使用普通 LDAP 连接
									l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
								}

								if err != nil {
									log.Printf("重新连接失败: %v", err)
									dialog.ShowError(fmt.Errorf("连接已断开，重新连接失败: %v", err), myWindow)
									updateStatus("重新授权失败：连接已断开")
									return
								}
								defer l.Close()

								// 重新绑定
								if err := l.Bind(client.bindDN, client.bindPassword); err != nil {
									log.Printf("重新绑定失败: %v", err)
									dialog.ShowError(fmt.Errorf("重新绑定失败: %v", err), myWindow)
									updateStatus("重新授权失败：无法重新绑定")
									return
								}
								log.Println("成功重新建立连接和绑定")
							} else {
								log.Println("LDAP连接状态正常")
							}

							// 1. 获取组的objectSid
							log.Printf("开始查找组 | DN: %s", ldapGroupEntry.Text)

							var groupResult *ldap.SearchResult
							var searchErr error
							maxRetries := 3
							var activeConn *ldap.Conn // 添加活动连接变量

							for attempt := 1; attempt <= maxRetries; attempt++ {
								if l == nil || attempt > 1 {
									log.Printf("尝试重新建立连接 (尝试 %d/%d)...", attempt, maxRetries)
									var connErr error

									if client.useTLS {
										// 使用 TLS 配置
										tlsConfig := &tls.Config{
											InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
										}
										activeConn, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
									} else {
										// 使用普通 LDAP 连接
										activeConn, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
									}

									if connErr != nil {
										log.Printf("连接失败: %v", connErr)
										continue
									}

									if bindErr := activeConn.Bind(client.bindDN, client.bindPassword); bindErr != nil {
										log.Printf("绑定失败: %v", bindErr)
										activeConn.Close()
										activeConn = nil
										continue
									}
								} else {
									activeConn = l // 如果是第一次尝试，使用现有连接
								}

								groupSearchRequest := ldap.NewSearchRequest(
									ldapGroupEntry.Text,
									ldap.ScopeBaseObject,
									ldap.NeverDerefAliases,
									0, 0, false,
									"(objectClass=group)",
									[]string{"objectSid", "cn", "distinguishedName"},
									nil,
								)

								groupResult, searchErr = activeConn.Search(groupSearchRequest)
								if searchErr != nil {
									log.Printf("搜索组失败 (尝试 %d/%d) | 错误: %v", attempt, maxRetries, searchErr)
									if ldapErr, ok := searchErr.(*ldap.Error); ok {
										log.Printf("LDAP错误详情 | 代码: %d | 消息: %s", ldapErr.ResultCode, ldapErr.Err.Error())
										// 如果是网络错误，关闭连接并重试
										if ldapErr.ResultCode == 200 {
											if activeConn != l { // 只关闭新建的连接
												activeConn.Close()
											}
											activeConn = nil
											continue
										}
									}
									// 其他错误，尝试在整个域中搜索
									break
								}
								// 搜索成功，跳出重试循环
								break
							}

							// 如果直接搜索失败，尝试在整个域中搜索
							if searchErr != nil || len(groupResult.Entries) == 0 {
								log.Printf("未找到组或搜索失败 | DN: %s", ldapGroupEntry.Text)
								// 尝试在整个域中搜索组
								domainDN := strings.Join(strings.Split(client.host, "."), ",DC=")
								domainDN = "DC=" + domainDN
								log.Printf("在整个域中搜索组 | 基准DN: %s", domainDN)

								// 从组DN中提取CN
								groupCN := strings.Split(ldapGroupEntry.Text, ",")[0]
								if strings.HasPrefix(groupCN, "CN=") {
									groupCN = strings.TrimPrefix(groupCN, "CN=")
								}

								broadSearchRequest := ldap.NewSearchRequest(
									domainDN,
									ldap.ScopeWholeSubtree,
									ldap.NeverDerefAliases,
									0, 0, false,
									fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupCN)),
									[]string{"objectSid", "distinguishedName"},
									nil,
								)

								for attempt := 1; attempt <= maxRetries; attempt++ {
									if activeConn == nil || attempt > 1 {
										log.Printf("尝试重新建立连接进行域搜索 (尝试 %d/%d)...", attempt, maxRetries)
										var connErr error

										if client.useTLS {
											// 使用 TLS 配置
											tlsConfig := &tls.Config{
												InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
											}
											activeConn, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
										} else {
											// 使用普通 LDAP 连接
											activeConn, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
										}

										if connErr != nil {
											log.Printf("连接失败: %v", connErr)
											continue
										}

										if bindErr := activeConn.Bind(client.bindDN, client.bindPassword); bindErr != nil {
											log.Printf("绑定失败: %v", bindErr)
											activeConn.Close()
											activeConn = nil
											continue
										}
									}

									groupResult, searchErr = activeConn.Search(broadSearchRequest)
									if searchErr != nil {
										log.Printf("域搜索失败 (尝试 %d/%d) | 错误: %v", attempt, maxRetries, searchErr)
										if ldapErr, ok := searchErr.(*ldap.Error); ok && ldapErr.ResultCode == 200 {
											if activeConn != l { // 只关闭新建的连接
												activeConn.Close()
											}
											activeConn = nil
											continue
										}
										// 其他错误直接跳出
										break
									}
									// 搜索成功，跳出重试循环
									break
								}

								if searchErr != nil {
									log.Printf("域范围搜索失败 | 错误: %v", searchErr)
									updateStatus(fmt.Sprintf("在域中搜索组失败: %v", searchErr))
									if activeConn != nil && activeConn != l {
										activeConn.Close()
									}
									return
								}

								if len(groupResult.Entries) == 0 {
									updateStatus("在整个域中都未找到指定的组，请确认组是否存在")
									if activeConn != nil && activeConn != l {
										activeConn.Close()
									}
									return
								}

								// 找到组，更新组DN
								foundGroupDN := groupResult.Entries[0].DN
								log.Printf("找到组 | DN: %s", foundGroupDN)
								ldapGroupEntry.SetText(foundGroupDN)
							}

							// 2. 创建修改请求
							modifyRequest := ldap.NewModifyRequest(ldapGroupEntry.Text, nil)

							// 3. 设置组类型为全局安全组
							modifyRequest.Replace("groupType", []string{"-2147483646"})

							// 4. 更新组描述
							modifyRequest.Replace("description", []string{"LDAP Authentication Group"})

							// 执行修改
							log.Printf("执行修改请求 | DN: %s | 属性数: %d", ldapGroupEntry.Text, len(modifyRequest.Changes))
							if err := activeConn.Modify(modifyRequest); err != nil {
								log.Printf("重新授权失败 | 错误类型: %T | 详细错误: %v", err, err)
								if ldapErr, ok := err.(*ldap.Error); ok {
									log.Printf("LDAP错误详情 | 代码: %d | 消息: %s | 匹配的DN: %s",
										ldapErr.ResultCode, ldapErr.Err.Error(), ldapErr.MatchedDN)
								}
								dialog.ShowError(fmt.Errorf("重新授权失败: %v", err), myWindow)
								updateStatus("组重新授权失败")
							} else {
								log.Printf("重新授权成功 | DN: %s", ldapGroupEntry.Text)
								updateStatus(fmt.Sprintf("组重新授权成功：%s", ldapGroupEntry.Text))
							}

							// 最后清理连接
							if activeConn != nil && activeConn != l {
								activeConn.Close()
							}
						} else {
							updateStatus("保持现有组权限不变：" + foundGroupDN)
						}
					}, myWindow)
				ldapGroupEntry.SetText(foundGroupDN) // 标准化显示格式
				return
			}

			// 原有的移动组逻辑保持不变
			dialog.ShowConfirm("组已存在",
				fmt.Sprintf("发现同名组：\n%s\n\n当前输入位置：\n%s\n\n是否要移动组？",
					foundGroupDN,
					ldapGroupEntry.Text),
				func(move bool) {
					if move {
						updateStatus(fmt.Sprintf("正在移动组 %s -> %s", foundGroupDN, ldapGroupEntry.Text))
						log.Printf("开始移动组操作 | 源DN: %s | 目标DN: %s", foundGroupDN, ldapGroupEntry.Text)

						if err := client.moveUser(foundGroupDN, ldapGroupEntry.Text); err != nil {
							log.Printf("组移动失败 | 错误详情: %v | 源DN: %s | 目标DN: %s",
								err, foundGroupDN, ldapGroupEntry.Text)
							dialog.ShowError(fmt.Errorf("移动失败: %v", err), myWindow)
							updateStatus("组移动失败")
						} else {
							log.Printf("组移动成功 | 新位置: %s", ldapGroupEntry.Text)
							updateStatus("组移动成功")
							ldapGroupEntry.SetText(ldapGroupEntry.Text) // 保持新位置
						}
					} else {
						// 自动填充查询到的组位置
						ldapGroupEntry.SetText(foundGroupDN)
						updateStatus("已使用现有组位置：" + foundGroupDN)
					}
				}, myWindow)
			return
		}

		// 不存在则继续创建流程
		updateStatus("未找到同名组，准备创建新组...")

		// 确保目标路径存在
		parentDN := strings.SplitN(ldapGroupEntry.Text, ",", 2)[1]
		if err := client.ensureDNExists(parentDN); err != nil {
			dialog.ShowError(fmt.Errorf("创建路径失败: %v", err), myWindow)
			updateStatus("创建组失败：无法创建目标路径")
			return
		}

		// 创建新组
		addRequest := ldap.NewAddRequest(ldapGroupEntry.Text, nil)
		addRequest.Attribute("objectClass", []string{"top", "group"})
		addRequest.Attribute("groupType", []string{"-2147483646"}) // 全局安全组

		// 从DN中提取CN作为sAMAccountName
		cn := strings.TrimPrefix(strings.SplitN(ldapGroupEntry.Text, ",", 2)[0], "CN=")
		addRequest.Attribute("sAMAccountName", []string{cn})

		if err := l.Add(addRequest); err != nil {
			dialog.ShowError(fmt.Errorf("创建组失败: %v", err), myWindow)
			updateStatus(fmt.Sprintf("创建组失败: %v", err))
			return
		}

		updateStatus(fmt.Sprintf("成功创建新组: %s", ldapGroupEntry.Text))
	})

	// 创建过滤器选择框
	filterSelect := widget.NewSelect(
		func() []string {
			var names []string
			for _, f := range commonFilters {
				names = append(names, f.name)
			}
			return names
		}(),
		nil,
	)
	filterSelect.SetSelected("sAMAccountName") // 设置默认选项

	// 创建过滤器描述标签
	filterDescription := widget.NewEntry()
	filterDescription.Disable() // 设置为只读，但允许选择和复制

	// 更新过滤器描述的函数
	updateFilterDescription := func(filterName string) {
		for _, f := range commonFilters {
			if f.name == filterName {
				filterDescription.Enable() // 临时启用以设置文本
				filterDescription.SetText(f.pattern)
				filterDescription.Disable() // 重新禁用以保持只读状态
				break
			}
		}
	}

	// 设置选择框回调
	filterSelect.OnChanged = updateFilterDescription
	updateFilterDescription("sAMAccountName") // 初始化描述

	// 创建过滤器输入框
	filterDNEntry := widget.NewEntry()
	filterDNEntry.SetPlaceHolder("请输入过滤器")
	filterDNEntry.SetText("(&(objectclass=user)(uid={%s}))") // 默认过滤器模板

	// 创建测试用户输入框
	testUserEntry := widget.NewEntry()
	testUserEntry.SetPlaceHolder("请输入测试用户名")

	// 创建测试密码输入框
	testPasswordEntry := widget.NewPasswordEntry()
	testPasswordEntry.SetPlaceHolder("请输入测试密码")

	// 状态区域布局容器（确保最小显示高度）
	background := canvas.NewRectangle(color.Transparent)
	background.SetMinSize(fyne.NewSize(400, 60)) // 最小尺寸约束
	statusContainer := container.NewStack(
		background,
		container.NewVScroll(statusArea), // 垂直滚动容器
	)

	// ping测试按钮回调函数
	pingButton := widget.NewButton("连接测试", func() {
		host := domainEntry.Text
		if host == "" {
			updateStatus("请输入服务器地址")
			return
		}

		updateStatus("开始ping测试...")
		// 使用goroutine避免阻塞UI线程
		go func() {
			// 执行ping命令（Windows参数为-n，Linux/macOS为-c）
			cmd := exec.Command("ping", "-n", "4", host)
			output, err := cmd.CombinedOutput()
			if err != nil {
				updateStatus(fmt.Sprintf("ping测试失败: %v", err))
				return
			}

			// 转换中文编码（处理Windows下的GBK编码输出）
			decoder := simplifiedchinese.GBK.NewDecoder()
			utf8Output, _ := decoder.Bytes(output)
			outputStr := string(utf8Output)

			// 解析ping结果获取平均延迟
			var avgTime string
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				// 匹配中文和英文版本的延迟信息
				if strings.Contains(line, "平均 = ") || strings.Contains(line, "Average = ") {
					separator := " = "
					if strings.Contains(line, "平均 = ") {
						separator = "平均 = "
					} else {
						separator = "Average = "
					}

					parts := strings.Split(line, separator)
					if len(parts) > 1 {
						avgTime = strings.TrimSpace(parts[1])
						break
					}
				}
			}

			// 更新状态显示
			if avgTime != "" {
				updateStatus(fmt.Sprintf("ping测试结束，服务器可以连接，平均延迟为%s", avgTime))
			} else {
				updateStatus("ping测试结束，服务器可以连接，但无法获取平均延迟")
			}
		}()
	})

	// 端口测试按钮回调函数
	portTestButton := widget.NewButton("端口测试", func() {
		host := domainEntry.Text
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		// 使用3秒超时进行TCP连接测试
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			updateStatus(fmt.Sprintf("端口 %d 未开放", port))
		} else {
			conn.Close()
			updateStatus(fmt.Sprintf("端口 %d 已开放", port))
		}
	})

	// LDAP连接测试按钮回调函数
	adminTestButton := widget.NewButton("测试 LDAP 连接", func() {
		// 输入验证
		host := domainEntry.Text
		if host == "" {
			dialog.ShowError(fmt.Errorf("服务器地址不能为空"), myWindow)
			updateStatus("错误：请填写服务器地址")
			return
		}
		if host == "ldap.example.com" { // 防止使用示例地址
			dialog.ShowError(fmt.Errorf("请修改默认服务器地址"), myWindow)
			updateStatus("错误：请填写实际服务器地址")
			return
		}
		if portEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("服务器端口不能为空"), myWindow)
			updateStatus("错误：请填写服务器端口")
			return
		}
		if adminEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("admin DN不能为空"), myWindow)
			updateStatus("错误：请填写admin DN")
			return
		}
		if passwordEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("admin密码不能为空"), myWindow)
			updateStatus("错误：请填写admin密码")
			return
		}

		// 创建LDAP客户端实例
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       adminEntry.Text,
			bindPassword: passwordEntry.Text,
			updateFunc:   updateStatus,
			useTLS:       isSSLEnabled,
		}

		// 分步骤测试
		if client.isPortOpen() {
			serviceType := "LDAP"
			if client.useTLS {
				serviceType = "LDAPS"
			}
			updateStatus(fmt.Sprintf("%s 端口正常打开", serviceType))

			if client.testLDAPService() {
				updateStatus(fmt.Sprintf("%s 服务正常", serviceType))
			} else {
				updateStatus(fmt.Sprintf("%s 服务异常", serviceType))
			}
		} else {
			serviceType := "LDAP"
			if client.useTLS {
				serviceType = "LDAPS"
			}
			updateStatus(fmt.Sprintf("%s 端口未开放", serviceType))
		}
	})

	// 创建LDAP账号按钮回调函数
	createLdapButton := widget.NewButton("创建LDAP账号", func() {
		// 输入验证
		if ldapDNEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("LDAP DN不能为空"), myWindow)
			return
		}
		if isSSLEnabled && ldappasswordEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("SSL模式下LDAP密码不能为空"), myWindow)
			return
		}

		// 创建 LDAP 客户端实例
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       adminEntry.Text,
			bindPassword: passwordEntry.Text,
			updateFunc:   updateStatus,
			useTLS:       isSSLEnabled,
		}

		// 先检查端口连通性
		if !client.isPortOpen() {
			updateStatus(fmt.Sprintf("端口 %d 未开放", port))
			return
		}

		// 验证管理员凭证
		if !client.testLDAPService() {
			dialog.ShowError(fmt.Errorf("管理员认证失败\n可能原因：\n1. 密码错误\n2. DN格式错误\n3. 权限不足"), myWindow)
			updateStatus("管理员凭证验证失败")
			return
		}

		// 从输入的DN中提取CN
		enteredCN := strings.SplitN(ldapDNEntry.Text, ",", 2)[0]
		if !strings.HasPrefix(enteredCN, "CN=") {
			updateStatus("无效的DN格式")
			return
		}
		userName := strings.TrimPrefix(enteredCN, "CN=")

		// 修改搜索请求为按CN查询
		searchRequest := ldap.NewSearchRequest(
			searchDNEntry.Text,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			fmt.Sprintf("(&(objectClass=user)(cn=%s))", ldap.EscapeFilter(userName)),
			[]string{"dn"},
			nil,
		)

		log.Println("尝试连接到 LDAP 服务器...")
		var l *ldap.Conn
		var connErr error

		if client.useTLS {
			// 使用 TLS 配置
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
			}
			l, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
		} else {
			// 使用普通 LDAP 连接
			l, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
		}

		if connErr != nil {
			updateStatus(fmt.Sprintf("连接失败: %v", connErr))
			log.Printf("连接失败: %v", connErr)
			if netErr, ok := connErr.(net.Error); ok {
				if netErr.Timeout() {
					log.Println("连接超时")
				}
				if netErr.Temporary() {
					log.Println("临时网络错误")
				}
			}
			log.Printf("详细错误信息: %T - %v", connErr, connErr)
			return
		}
		log.Println("连接到 LDAP 服务器成功")
		defer l.Close()

		log.Println("尝试绑定到 LDAP 服务器...")
		if err := l.Bind(client.bindDN, client.bindPassword); err != nil {
			updateStatus(fmt.Sprintf("绑定失败: %v", err))
			log.Printf("绑定失败: %v", err)
			return
		}
		log.Println("绑定到 LDAP 服务器成功")

		log.Println("执行搜索请求...")
		sr, err := l.Search(searchRequest)
		if err != nil {
			updateStatus(fmt.Sprintf("搜索失败: %v", err))
			return
		}

		// 检查是否存在同名用户
		if len(sr.Entries) > 0 {
			foundUserDN := sr.Entries[0].DN

			// 当DN完全相同时（不区分大小写）
			if strings.EqualFold(strings.ToLower(foundUserDN), strings.ToLower(ldapDNEntry.Text)) {
				// 提示是否更新用户权限
				dialog.ShowConfirm("用户已存在",
					fmt.Sprintf("用户已存在且位置相同：\n%s\n\n是否要更新用户的权限组设置？", foundUserDN),
					func(update bool) {
						if update {
							updateStatus("开始更新用户权限组设置...")

							// 1. 获取组的objectSid
							log.Printf("开始查找组 | DN: %s", ldapGroupEntry.Text)

							var groupResult *ldap.SearchResult
							var searchErr error
							maxRetries := 3
							var activeConn *ldap.Conn // 添加活动连接变量

							for attempt := 1; attempt <= maxRetries; attempt++ {
								if l == nil || attempt > 1 {
									log.Printf("尝试重新建立连接 (尝试 %d/%d)...", attempt, maxRetries)
									var connErr error

									if client.useTLS {
										// 使用 TLS 配置
										tlsConfig := &tls.Config{
											InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
										}
										activeConn, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
									} else {
										// 使用普通 LDAP 连接
										activeConn, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
									}

									if connErr != nil {
										log.Printf("连接失败: %v", connErr)
										continue
									}

									if bindErr := activeConn.Bind(client.bindDN, client.bindPassword); bindErr != nil {
										log.Printf("绑定失败: %v", bindErr)
										activeConn.Close()
										activeConn = nil
										continue
									}
								} else {
									activeConn = l // 如果是第一次尝试，使用现有连接
								}

								groupSearchRequest := ldap.NewSearchRequest(
									ldapGroupEntry.Text,
									ldap.ScopeBaseObject,
									ldap.NeverDerefAliases,
									0, 0, false,
									"(objectClass=group)",
									[]string{"objectSid", "cn", "distinguishedName"},
									nil,
								)

								groupResult, searchErr = activeConn.Search(groupSearchRequest)
								if searchErr != nil {
									log.Printf("搜索组失败 (尝试 %d/%d) | 错误: %v", attempt, maxRetries, searchErr)
									if ldapErr, ok := searchErr.(*ldap.Error); ok {
										log.Printf("LDAP错误详情 | 代码: %d | 消息: %s", ldapErr.ResultCode, ldapErr.Err.Error())
										// 如果是网络错误，关闭连接并重试
										if ldapErr.ResultCode == 200 {
											if activeConn != l { // 只关闭新建的连接
												activeConn.Close()
											}
											activeConn = nil
											continue
										}
									}
									// 其他错误，尝试在整个域中搜索
									break
								}
								// 搜索成功，跳出重试循环
								break
							}

							// 如果直接搜索失败，尝试在整个域中搜索
							if searchErr != nil || len(groupResult.Entries) == 0 {
								log.Printf("未找到组或搜索失败 | DN: %s", ldapGroupEntry.Text)
								// 尝试在整个域中搜索组
								domainDN := strings.Join(strings.Split(client.host, "."), ",DC=")
								domainDN = "DC=" + domainDN
								log.Printf("在整个域中搜索组 | 基准DN: %s", domainDN)

								// 从组DN中提取CN
								groupCN := strings.Split(ldapGroupEntry.Text, ",")[0]
								if strings.HasPrefix(groupCN, "CN=") {
									groupCN = strings.TrimPrefix(groupCN, "CN=")
								}

								broadSearchRequest := ldap.NewSearchRequest(
									domainDN,
									ldap.ScopeWholeSubtree,
									ldap.NeverDerefAliases,
									0, 0, false,
									fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupCN)),
									[]string{"objectSid", "distinguishedName"},
									nil,
								)

								for attempt := 1; attempt <= maxRetries; attempt++ {
									if activeConn == nil || attempt > 1 {
										log.Printf("尝试重新建立连接进行域搜索 (尝试 %d/%d)...", attempt, maxRetries)
										var connErr error

										if client.useTLS {
											// 使用 TLS 配置
											tlsConfig := &tls.Config{
												InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
											}
											activeConn, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
										} else {
											// 使用普通 LDAP 连接
											activeConn, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
										}

										if connErr != nil {
											log.Printf("连接失败: %v", connErr)
											continue
										}

										if bindErr := activeConn.Bind(client.bindDN, client.bindPassword); bindErr != nil {
											log.Printf("绑定失败: %v", bindErr)
											activeConn.Close()
											activeConn = nil
											continue
										}
									}

									groupResult, searchErr = activeConn.Search(broadSearchRequest)
									if searchErr != nil {
										log.Printf("域搜索失败 (尝试 %d/%d) | 错误: %v", attempt, maxRetries, searchErr)
										if ldapErr, ok := searchErr.(*ldap.Error); ok && ldapErr.ResultCode == 200 {
											if activeConn != l { // 只关闭新建的连接
												activeConn.Close()
											}
											activeConn = nil
											continue
										}
										// 其他错误直接跳出
										break
									}
									// 搜索成功，跳出重试循环
									break
								}

								if searchErr != nil {
									log.Printf("域范围搜索失败 | 错误: %v", searchErr)
									updateStatus(fmt.Sprintf("在域中搜索组失败: %v", searchErr))
									if activeConn != nil && activeConn != l {
										activeConn.Close()
									}
									return
								}

								if len(groupResult.Entries) == 0 {
									updateStatus("在整个域中都未找到指定的组，请确认组是否存在")
									if activeConn != nil && activeConn != l {
										activeConn.Close()
									}
									return
								}

								// 找到组，更新组DN
								foundGroupDN := groupResult.Entries[0].DN
								log.Printf("找到组 | DN: %s", foundGroupDN)
								ldapGroupEntry.SetText(foundGroupDN)
							}

							// 2. 创建修改请求
							modifyRequest := ldap.NewModifyRequest(ldapGroupEntry.Text, nil)

							// 3. 设置组类型为全局安全组
							modifyRequest.Replace("groupType", []string{"-2147483646"})

							// 4. 更新组描述
							modifyRequest.Replace("description", []string{"LDAP Authentication Group"})

							// 执行修改
							log.Printf("执行修改请求 | DN: %s | 属性数: %d", ldapGroupEntry.Text, len(modifyRequest.Changes))
							if err := activeConn.Modify(modifyRequest); err != nil {
								log.Printf("重新授权失败 | 错误类型: %T | 详细错误: %v", err, err)
								if ldapErr, ok := err.(*ldap.Error); ok {
									log.Printf("LDAP错误详情 | 代码: %d | 消息: %s | 匹配的DN: %s",
										ldapErr.ResultCode, ldapErr.Err.Error(), ldapErr.MatchedDN)
								}
								dialog.ShowError(fmt.Errorf("重新授权失败: %v", err), myWindow)
								updateStatus("组重新授权失败")
							} else {
								log.Printf("重新授权成功 | DN: %s", ldapGroupEntry.Text)
								updateStatus(fmt.Sprintf("组重新授权成功：%s", ldapGroupEntry.Text))
							}

							// 最后清理连接
							if activeConn != nil && activeConn != l {
								activeConn.Close()
							}
						} else {
							updateStatus("保持用户现有权限不变")
						}
					}, myWindow)
				return
			}

			// 提示是否移动用户
			dialog.ShowConfirm("用户已存在",
				fmt.Sprintf("发现同名用户：\n%s\n\n当前输入位置：\n%s\n\n是否要移动用户并更新权限组？",
					foundUserDN,
					ldapDNEntry.Text),
				func(move bool) {
					if move {
						updateStatus(fmt.Sprintf("正在移动用户 %s -> %s", foundUserDN, ldapDNEntry.Text))
						log.Printf("开始移动用户操作 | 源DN: %s | 目标DN: %s", foundUserDN, ldapDNEntry.Text)

						if err := client.moveUser(foundUserDN, ldapDNEntry.Text); err != nil {
							log.Printf("用户移动失败 | 错误详情: %v | 源DN: %s | 目标DN: %s",
								err, foundUserDN, ldapDNEntry.Text)
							dialog.ShowError(fmt.Errorf("移动失败: %v", err), myWindow)
							updateStatus("用户移动失败")
							return
						}

						log.Printf("用户移动成功 | 新位置: %s", ldapDNEntry.Text)
						updateStatus("用户移动成功，开始更新权限组...")

						// 移动成功后更新权限组
						// 1. 获取组的objectSid
						log.Printf("开始查找组 | DN: %s", ldapGroupEntry.Text)

						var groupResult *ldap.SearchResult
						var searchErr error
						maxRetries := 3
						var activeConn *ldap.Conn // 添加活动连接变量

						for attempt := 1; attempt <= maxRetries; attempt++ {
							if l == nil || attempt > 1 {
								log.Printf("尝试重新建立连接 (尝试 %d/%d)...", attempt, maxRetries)
								var connErr error

								if client.useTLS {
									// 使用 TLS 配置
									tlsConfig := &tls.Config{
										InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
									}
									activeConn, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
								} else {
									// 使用普通 LDAP 连接
									activeConn, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
								}

								if connErr != nil {
									log.Printf("连接失败: %v", connErr)
									continue
								}

								if bindErr := activeConn.Bind(client.bindDN, client.bindPassword); bindErr != nil {
									log.Printf("绑定失败: %v", bindErr)
									activeConn.Close()
									activeConn = nil
									continue
								}
							} else {
								activeConn = l // 如果是第一次尝试，使用现有连接
							}

							groupSearchRequest := ldap.NewSearchRequest(
								ldapGroupEntry.Text,
								ldap.ScopeBaseObject,
								ldap.NeverDerefAliases,
								0, 0, false,
								"(objectClass=group)",
								[]string{"objectSid", "cn", "distinguishedName"},
								nil,
							)

							groupResult, searchErr = activeConn.Search(groupSearchRequest)
							if searchErr != nil {
								log.Printf("搜索组失败 (尝试 %d/%d) | 错误: %v", attempt, maxRetries, searchErr)
								if ldapErr, ok := searchErr.(*ldap.Error); ok {
									log.Printf("LDAP错误详情 | 代码: %d | 消息: %s", ldapErr.ResultCode, ldapErr.Err.Error())
									// 如果是网络错误，关闭连接并重试
									if ldapErr.ResultCode == 200 {
										if activeConn != l { // 只关闭新建的连接
											activeConn.Close()
										}
										activeConn = nil
										continue
									}
								}
								// 其他错误，尝试在整个域中搜索
								break
							}
							// 搜索成功，跳出重试循环
							break
						}

						// 如果直接搜索失败，尝试在整个域中搜索
						if searchErr != nil || len(groupResult.Entries) == 0 {
							log.Printf("未找到组或搜索失败 | DN: %s", ldapGroupEntry.Text)
							// 尝试在整个域中搜索组
							domainDN := strings.Join(strings.Split(client.host, "."), ",DC=")
							domainDN = "DC=" + domainDN
							log.Printf("在整个域中搜索组 | 基准DN: %s", domainDN)

							// 从组DN中提取CN
							groupCN := strings.Split(ldapGroupEntry.Text, ",")[0]
							if strings.HasPrefix(groupCN, "CN=") {
								groupCN = strings.TrimPrefix(groupCN, "CN=")
							}

							broadSearchRequest := ldap.NewSearchRequest(
								domainDN,
								ldap.ScopeWholeSubtree,
								ldap.NeverDerefAliases,
								0, 0, false,
								fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupCN)),
								[]string{"objectSid", "distinguishedName"},
								nil,
							)

							for attempt := 1; attempt <= maxRetries; attempt++ {
								if activeConn == nil || attempt > 1 {
									log.Printf("尝试重新建立连接进行域搜索 (尝试 %d/%d)...", attempt, maxRetries)
									var connErr error

									if client.useTLS {
										// 使用 TLS 配置
										tlsConfig := &tls.Config{
											InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
										}
										activeConn, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.host, client.port), tlsConfig)
									} else {
										// 使用普通 LDAP 连接
										activeConn, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
									}

									if connErr != nil {
										log.Printf("连接失败: %v", connErr)
										continue
									}

									if bindErr := activeConn.Bind(client.bindDN, client.bindPassword); bindErr != nil {
										log.Printf("绑定失败: %v", bindErr)
										activeConn.Close()
										activeConn = nil
										continue
									}
								}

								groupResult, searchErr = activeConn.Search(broadSearchRequest)
								if searchErr != nil {
									log.Printf("域搜索失败 (尝试 %d/%d) | 错误: %v", attempt, maxRetries, searchErr)
									if ldapErr, ok := searchErr.(*ldap.Error); ok && ldapErr.ResultCode == 200 {
										if activeConn != l { // 只关闭新建的连接
											activeConn.Close()
										}
										activeConn = nil
										continue
									}
									// 其他错误直接跳出
									break
								}
								// 搜索成功，跳出重试循环
								break
							}

							if searchErr != nil {
								log.Printf("域范围搜索失败 | 错误: %v", searchErr)
								updateStatus(fmt.Sprintf("在域中搜索组失败: %v", searchErr))
								if activeConn != nil && activeConn != l {
									activeConn.Close()
								}
								return
							}

							if len(groupResult.Entries) == 0 {
								updateStatus("在整个域中都未找到指定的组，请确认组是否存在")
								if activeConn != nil && activeConn != l {
									activeConn.Close()
								}
								return
							}

							// 找到组，更新组DN
							foundGroupDN := groupResult.Entries[0].DN
							log.Printf("找到组 | DN: %s", foundGroupDN)
							ldapGroupEntry.SetText(foundGroupDN)
						}

						// 2. 修改用户的primaryGroupID
						modifyRequest := ldap.NewModifyRequest(ldapDNEntry.Text, nil)
						modifyRequest.Replace("primaryGroupID", []string{fmt.Sprintf("%d", binary.LittleEndian.Uint32(groupResult.Entries[0].GetRawAttributeValue("objectSid")[:4]))})

						if err := activeConn.Modify(modifyRequest); err != nil {
							updateStatus(fmt.Sprintf("设置主要组失败: %v", err))
							return
						}

						// 4. 将用户添加到新组的member属性中
						groupModifyRequest := ldap.NewModifyRequest(ldapGroupEntry.Text, nil)
						groupModifyRequest.Add("member", []string{ldapDNEntry.Text})

						if err := activeConn.Modify(groupModifyRequest); err != nil {
							// 忽略"已存在"错误
							if ldapErr, ok := err.(*ldap.Error); !ok || ldapErr.ResultCode != ldap.LDAPResultEntryAlreadyExists {
								updateStatus(fmt.Sprintf("添加用户到组失败: %v", err))
								return
							}
						}

						// 5. 移除用户的其他组成员身份
						userSearchRequest := ldap.NewSearchRequest(
							ldapDNEntry.Text,
							ldap.ScopeBaseObject,
							ldap.NeverDerefAliases,
							0, 0, false,
							"(objectClass=user)",
							[]string{"memberOf"},
							nil,
						)

						userResult, err := activeConn.Search(userSearchRequest)
						if err == nil && len(userResult.Entries) > 0 {
							for _, group := range userResult.Entries[0].GetAttributeValues("memberOf") {
								if group != ldapGroupEntry.Text {
									removeGroupRequest := ldap.NewModifyRequest(group, nil)
									removeGroupRequest.Delete("member", []string{ldapDNEntry.Text})
									if err := activeConn.Modify(removeGroupRequest); err != nil {
										updateStatus(fmt.Sprintf("从组 %s 移除用户失败: %v", group, err))
									} else {
										updateStatus(fmt.Sprintf("已从组 %s 移除用户", group))
									}
								}
							}
						}

						updateStatus("用户移动和权限组设置完成")
					} else {
						// 自动填充查询到的用户位置
						ldapDNEntry.SetText(foundUserDN)
						updateStatus("已使用现有用户位置：" + foundUserDN)
					}
				}, myWindow)
			return
		}

		// 不存在则继续创建流程
		updateStatus("未找到同名用户，准备创建新用户...")

		// 确保目标路径存在
		parentDN := strings.SplitN(ldapDNEntry.Text, ",", 2)[1]
		if err := client.ensureDNExists(parentDN); err != nil {
			dialog.ShowError(fmt.Errorf("创建路径失败: %v", err), myWindow)
			updateStatus("创建用户失败：无法创建目标路径")
			return
		}

		// 根据SSL状态选择创建用户的函数
		if isSSLEnabled {
			// SSL模式：创建启用账号并设置密码
			err := createUserWithSSL(l, &client, ldapDNEntry.Text, userName, ldappasswordEntry.Text, client.host, myWindow, updateStatus)
			if err != nil {
				dialog.ShowError(err, myWindow)
				updateStatus(fmt.Sprintf("创建用户失败: %v", err))
				return
			}
		} else {
			// 非SSL模式：创建禁用账号
			err := createUserWithoutSSL(l, ldapDNEntry.Text, userName, client.host, updateStatus)
			if err != nil {
				dialog.ShowError(err, myWindow)
				updateStatus(fmt.Sprintf("创建用户失败: %v", err))
				return
			}
		}
	})

	// 管理员验证用户按钮回调函数
	adminTestUserButton := widget.NewButton("admin账号验证用户", func() {
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			updateStatus("请输入测试用户名和密码")
			return
		}

		// 获取选定的过滤器模式
		var filterPattern string
		for _, f := range commonFilters {
			if f.name == filterSelect.Selected {
				filterPattern = f.pattern
				break
			}
		}

		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       adminEntry.Text,
			bindPassword: passwordEntry.Text,
			updateFunc:   updateStatus,
			useTLS:       isSSLEnabled,
		}

		updateStatus(fmt.Sprintf("使用 %s 过滤器开始验证用户...", filterSelect.Selected))
		if client.testUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, filterPattern) {
			updateStatus("测试用户验证成功")
		} else {
			updateStatus("测试用户验证失败")
		}
	})

	// LDAP账号验证用户按钮回调函数
	ldapTestUserButton := widget.NewButton("LDAP账号验证用户", func() {
		// 输入验证（与管理员验证类似）
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			updateStatus("请输入测试用户名和密码")
			return
		}

		// 获取选定的过滤器模式
		var filterPattern string
		for _, f := range commonFilters {
			if f.name == filterSelect.Selected {
				filterPattern = f.pattern
				break
			}
		}

		// 创建LDAP客户端实例（使用LDAP账号凭证）
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       ldapDNEntry.Text,
			bindPassword: ldappasswordEntry.Text,
			updateFunc:   updateStatus,
			useTLS:       isSSLEnabled,
		}

		updateStatus(fmt.Sprintf("使用 %s 过滤器开始验证用户...", filterSelect.Selected))
		if client.testUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, filterPattern) {
			updateStatus("测试用户验证成功")
		} else {
			updateStatus("测试用户验证失败")
		}
	})

	// 创建一个函数来生成统一宽度的标签
	makeLabel := func(text string) fyne.CanvasObject {
		label := widget.NewLabel(text)
		label.TextStyle = fyne.TextStyle{Bold: true} // 粗体显示
		label.Alignment = fyne.TextAlignTrailing     // 右对齐

		// 使用容器实现固定宽度布局
		return container.NewHBox(
			layout.NewSpacer(), // 左侧弹性空间
			container.NewGridWrap( // 固定宽度容器
				fyne.NewSize(100, 0), // 宽度100像素，高度自适应
				label,
			),
		)
	}

	// 使用 Border 布局来实现自动拉伸
	formContainer := container.NewVBox(
		container.NewBorder(nil, nil, makeLabel("服务器地址:"), pingButton,
			domainEntry,
		),
		container.NewBorder(nil, nil, makeLabel("服务器端口:"), container.NewHBox(
			widget.NewCheck("SSL支持", func(checked bool) {
				isSSLEnabled = checked // 更新全局SSL状态
				if checked {
					portEntry.SetDefaultPort(true)                         // SSL端口
					ldappasswordEntry.SetPlaceHolder("SSL模式下创建的用户是可以直接用的") // 更新占位符提示
				} else {
					portEntry.SetDefaultPort(false)                          // 标准端口
					ldappasswordEntry.SetPlaceHolder("非SSL模式创建的用户是没有密码停用的）") // 更新占位符提示
				}
			}),
			portTestButton,
		),
			portEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Admin DN:"), nil,
			adminEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Admin密码:"), adminTestButton,
			passwordEntry,
		),
		// Add the LDAP permissions group entry here
		container.NewBorder(nil, nil, makeLabel("Ldap权限组:"), groupButton,
			ldapGroupEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Ldap DN:"), nil,
			ldapDNEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Ldap密码:"), createLdapButton,
			ldappasswordEntry,
		),
		container.NewBorder(nil, nil, makeLabel("搜索DN:"), nil,
			searchDNEntry,
		),
		container.NewBorder(nil, nil, makeLabel("过滤器:"), nil,
			container.NewVBox(
				filterSelect,
				filterDescription,
			),
		),
		container.NewBorder(nil, nil, makeLabel("测试用户名:"), adminTestUserButton,
			testUserEntry,
		),
		container.NewBorder(nil, nil, makeLabel("测试密码:"), ldapTestUserButton,
			testPasswordEntry,
		),
	)

	// 修改窗口布局
	content := container.NewBorder(
		// 顶部固定内容
		container.NewVBox(
			widget.NewLabel("LDAP 服务测试"),
			formContainer,
		),
		nil, // 底部
		nil, // 左侧
		nil, // 右侧
		// 中间自动填充的内容
		statusContainer,
	)

	myWindow.SetContent(content)

	// 增加窗口的默认大小，使状态区域有足够的显示空间
	myWindow.Resize(fyne.NewSize(600, 600))
	myWindow.ShowAndRun()
}
