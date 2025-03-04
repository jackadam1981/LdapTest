//go:build linux || darwin || windows
// +build linux darwin windows

package main

import (
	"fmt"
	"image/color"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

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
}

// 全局变量
var (
	isSSLEnabled bool // SSL支持状态
)

// encodePassword 将密码编码为Active Directory所需的格式
func encodePassword(password string) string {
	// Active Directory需要UTF-16LE编码的密码，并用双引号包围
	utf16le := make([]byte, 0, len(password)*2+2)
	utf16le = append(utf16le, '"')
	for _, r := range password {
		utf16le = append(utf16le, byte(r), byte(r>>8))
	}
	utf16le = append(utf16le, '"')
	return string(utf16le)
}

// isPortOpen 检查LDAP服务端口是否开放
// 返回值：bool - true表示端口开放，false表示关闭
func (client *LDAPClient) isPortOpen() bool {
	address := net.JoinHostPort(client.host, fmt.Sprintf("%d", client.port))
	// 使用TCP协议尝试建立连接
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return false
	}
	conn.Close() // 关闭测试连接
	return true
}

// getURL 根据SSL状态返回合适的LDAP URL
func (client *LDAPClient) getURL() string {
	scheme := "ldap"
	if isSSLEnabled {
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

	// 建立新连接
	var err error
	client.conn, err = ldap.DialURL(client.getURL())
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
	err := client.bind(bindDN, bindPassword)
	if err != nil {
		// 如果绑定失败，尝试重新连接一次
		client.close()
		if err := client.connect(); err != nil {
			return fmt.Errorf("重新连接失败: %v", err)
		}
		// 重试绑定
		if err := client.bind(bindDN, bindPassword); err != nil {
			return fmt.Errorf("重新绑定失败: %v", err)
		}
	}
	return nil
}

// testLDAPService 测试LDAP服务连通性
func (client *LDAPClient) testLDAPService() bool {
	defer client.close() // 确保连接最后被关闭

	if err := client.bindWithRetry(client.bindDN, client.bindPassword); err != nil {
		log.Printf("服务测试失败: %v", err)
		return false
	}

	log.Println("LDAP服务验证成功")
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
	url := fmt.Sprintf("ldap://%s:%d", client.host, client.port)
	l, err := ldap.DialURL(url)
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
	ldapGroupEntry := widget.NewSelectEntry([]string{"Group1", "Group2", "Group3"})
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
		l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", client.host, client.port))
		if err != nil {
			updateStatus(fmt.Sprintf("连接失败: %v", err))
			log.Printf("连接失败: %v", err)
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() {
					log.Println("连接超时")
				}
				if netErr.Temporary() {
					log.Println("临时网络错误")
				}
			}
			log.Printf("详细错误信息: %T - %v", err, err)
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
								var err error
								l, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", client.host, client.port))
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
							}

							// 验证连接是否仍然有效
							searchRequest := ldap.NewSearchRequest(
								"",
								ldap.ScopeBaseObject,
								ldap.NeverDerefAliases,
								0, 0, false,
								"(objectClass=*)",
								[]string{"supportedLDAPVersion"},
								nil,
							)

							log.Println("验证LDAP连接状态...")
							_, err := l.Search(searchRequest)
							if err != nil {
								log.Printf("连接状态检查失败: %v", err)
								// 尝试重新连接
								l, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", client.host, client.port))
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

							// 1. 获取组的 SID
							log.Printf("开始获取组SID | DN: %s", foundGroupDN)
							searchRequest = ldap.NewSearchRequest(
								foundGroupDN,
								ldap.ScopeBaseObject,
								ldap.NeverDerefAliases,
								0, 0, false,
								"(objectClass=group)",
								[]string{"objectSid", "nTSecurityDescriptor"},
								nil,
							)

							sr, err := l.Search(searchRequest)
							if err != nil {
								log.Printf("获取组SID失败 | 错误类型: %T | 错误: %v", err, err)
								if ldapErr, ok := err.(*ldap.Error); ok {
									log.Printf("LDAP错误详情 | 代码: %d | 消息: %s", ldapErr.ResultCode, ldapErr.Err.Error())
								}
								dialog.ShowError(fmt.Errorf("获取组SID失败: %v", err), myWindow)
								updateStatus("重新授权失败：无法获取组SID")
								return
							}

							if len(sr.Entries) == 0 {
								log.Printf("未找到组 | DN: %s", foundGroupDN)
								updateStatus("重新授权失败：找不到组")
								return
							}

							log.Printf("成功获取组信息 | 条目数: %d", len(sr.Entries))

							// 2. 创建修改请求
							modifyRequest := ldap.NewModifyRequest(foundGroupDN, nil)

							// 3. 设置组类型为全局安全组
							modifyRequest.Replace("groupType", []string{"-2147483646"})

							// 4. 更新组描述
							modifyRequest.Replace("description", []string{"LDAP Authentication Group"})

							// 执行修改
							log.Printf("执行修改请求 | DN: %s | 属性数: %d", foundGroupDN, len(modifyRequest.Changes))
							if err := l.Modify(modifyRequest); err != nil {
								log.Printf("重新授权失败 | 错误类型: %T | 详细错误: %v", err, err)
								if ldapErr, ok := err.(*ldap.Error); ok {
									log.Printf("LDAP错误详情 | 代码: %d | 消息: %s | 匹配的DN: %s",
										ldapErr.ResultCode, ldapErr.Err.Error(), ldapErr.MatchedDN)
								}
								dialog.ShowError(fmt.Errorf("重新授权失败: %v", err), myWindow)
								updateStatus("组重新授权失败")
							} else {
								log.Printf("重新授权成功 | DN: %s", foundGroupDN)
								updateStatus(fmt.Sprintf("组重新授权成功：%s", foundGroupDN))
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
		}

		// 分步骤测试
		if client.isPortOpen() {
			updateStatus("LDAP 端口正常打开")
			if client.testLDAPService() {
				updateStatus("LDAP 服务正常")
			} else {
				updateStatus("LDAP 服务异常")
			}
		} else {
			updateStatus("LDAP 端口未开放")
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
		l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", client.host, client.port))
		if err != nil {
			updateStatus(fmt.Sprintf("连接失败: %v", err))
			log.Printf("连接失败: %v", err)
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
				dialog.ShowError(fmt.Errorf("用户已存在且位置相同：%s", foundUserDN), myWindow)
				updateStatus("用户已存在且位置相同")
				return
			}

			// 提示是否移动用户
			dialog.ShowConfirm("用户已存在",
				fmt.Sprintf("发现同名用户：\n%s\n\n当前输入位置：\n%s\n\n是否要移动用户？",
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
						} else {
							log.Printf("用户移动成功 | 新位置: %s", ldapDNEntry.Text)
							updateStatus("用户移动成功")
							ldapDNEntry.SetText(ldapDNEntry.Text) // 保持新位置
						}
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

		// 创建新用户
		addRequest := ldap.NewAddRequest(ldapDNEntry.Text, nil)
		addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
		addRequest.Attribute("sAMAccountName", []string{userName})
		addRequest.Attribute("userAccountControl", []string{"2"}) // 禁用账户 (ACCOUNTDISABLE)

		// 添加必需的属性
		addRequest.Attribute("givenName", []string{userName})
		addRequest.Attribute("sn", []string{userName})
		addRequest.Attribute("displayName", []string{userName})
		addRequest.Attribute("name", []string{userName})
		addRequest.Attribute("userPrincipalName", []string{fmt.Sprintf("%s@%s", userName, client.host)})

		if err := l.Add(addRequest); err != nil {
			dialog.ShowError(fmt.Errorf("创建用户失败: %v", err), myWindow)
			updateStatus(fmt.Sprintf("创建用户失败: %v", err))
			return
		}

		// 用户创建成功后，设置额外的属性
		modifyRequest := ldap.NewModifyRequest(ldapDNEntry.Text, nil)
		modifyRequest.Replace("userAccountControl", []string{"2"}) // 确保账户禁用

		if err := l.Modify(modifyRequest); err != nil {
			updateStatus(fmt.Sprintf("警告：用户创建成功，但设置账户控制失败: %v", err))
		}

		updateStatus(fmt.Sprintf("成功创建新用户: %s（账户已禁用）", ldapDNEntry.Text))
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
