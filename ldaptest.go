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
	entry.ExtendBaseWidget(entry) // 必须调用以实现自定义组件
	return entry
}

// FocusGained 重写获取焦点事件处理
func (e *CustomPortEntry) FocusGained() {
	e.Entry.FocusGained() // 调用基类方法
	if e.Text == "" {
		e.SetText("389") // 保持默认提示值，但实际使用时会解析输入值
	}
}

// LDAPClient 结构体定义LDAP客户端配置
type LDAPClient struct {
	host         string       // LDAP服务器地址（IP或域名）
	port         int          // LDAP服务端口（默认389）
	bindDN       string       // 绑定用识别名（用于认证的Distinguished Name）
	bindPassword string       // 绑定用密码
	updateFunc   func(string) // 添加状态更新函数引用
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

// testLDAPService 测试LDAP服务连通性
// 返回值：bool - true表示服务正常，false表示异常
func (client *LDAPClient) testLDAPService() bool {
	url := fmt.Sprintf("ldap://%s:%d", client.host, client.port)
	// 建立LDAP连接
	l, err := ldap.DialURL(url)
	if err != nil {
		log.Println("连接失败:", err)
		return false
	}
	defer l.Close() // 确保连接关闭

	// 使用提供的凭证进行绑定验证
	err = l.Bind(client.bindDN, client.bindPassword)
	if err != nil {
		log.Println("绑定失败:", err)
		return false
	}

	log.Println("LDAP服务验证成功")
	return true
}

// testUserAuth 测试用户认证流程
// 参数：
//
//	testUser - 要测试的用户名
//	testPassword - 测试用户的密码
//	searchDN - 用户搜索的基准DN
//
// 返回值：bool - true表示认证成功，false表示失败
func (client *LDAPClient) testUserAuth(testUser, testPassword, searchDN string) bool {
	// 建立LDAP连接（同上）
	url := fmt.Sprintf("ldap://%s:%d", client.host, client.port)
	l, err := ldap.DialURL(url)
	if err != nil {
		log.Println("连接失败:", err)
		return false
	}
	defer l.Close()

	// 使用管理员凭证进行绑定
	if err := l.Bind(client.bindDN, client.bindPassword); err != nil {
		log.Println("管理员绑定失败:", err)
		return false
	}

	// 使用sAMAccountName进行AD兼容查询
	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", testUser), // AD专用属性
		[]string{"dn"},
		nil,
	)

	// 执行搜索
	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Println("搜索失败:", err)
		return false
	}

	// 验证搜索结果数量
	if len(sr.Entries) != 1 {
		log.Println("用户不存在或返回多个结果")
		return false
	}

	// 使用找到的用户DN进行绑定测试
	userDN := sr.Entries[0].DN
	if err := l.Bind(userDN, testPassword); err != nil {
		log.Println("用户绑定失败:", err)
		return false
	}

	log.Println("用户认证成功")
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

// ensureDNExists 递归检查/创建目标DN路径
func (client *LDAPClient) ensureDNExists(targetDN string) error {
	url := fmt.Sprintf("ldap://%s:%d", client.host, client.port)
	l, err := ldap.DialURL(url)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer l.Close()

	if err := l.Bind(client.bindDN, client.bindPassword); err != nil {
		return fmt.Errorf("管理员绑定失败: %v", err)
	}

	// 反向解析DN层级（从叶子节点到根节点）
	parts := strings.Split(targetDN, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		currentDN := strings.Join(parts[i:], ",")

		// 检查当前DN是否存在
		searchRequest := ldap.NewSearchRequest(
			currentDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		)

		if _, err := l.Search(searchRequest); err == nil {
			continue // DN已存在
		}

		// 创建不存在的OU
		if strings.HasPrefix(parts[i], "OU=") {
			addRequest := ldap.NewAddRequest(currentDN, nil)
			addRequest.Attribute("objectClass", []string{"organizationalUnit"})
			addRequest.Attribute("ou", []string{strings.TrimPrefix(parts[i], "OU=")})

			if err := l.Add(addRequest); err != nil {
				return fmt.Errorf("创建OU失败 %s: %v", currentDN, err)
			}
			client.updateFunc(fmt.Sprintf("已创建OU: %s", currentDN)) // 使用结构体中的引用
		}
	}
	return nil
}

// moveUser 执行用户移动操作
func (client *LDAPClient) moveUser(oldDN, newDN string) error {
	url := fmt.Sprintf("ldap://%s:%d", client.host, client.port)
	l, err := ldap.DialURL(url)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer l.Close()

	if err := l.Bind(client.bindDN, client.bindPassword); err != nil {
		return fmt.Errorf("管理员绑定失败: %v", err)
	}

	// 解析新DN的RDN和上级DN
	newRDNParts := strings.SplitN(newDN, ",", 2)
	if len(newRDNParts) != 2 {
		return fmt.Errorf("无效的新DN格式")
	}
	newRDN := newRDNParts[0]
	newSuperior := newRDNParts[1]

	// 创建ModifyDN请求
	modifyDNRequest := ldap.NewModifyDNRequest(
		oldDN,
		newRDN,
		true, // 删除旧RDN
		newSuperior,
	)

	// 执行移动操作
	if err := l.ModifyDN(modifyDNRequest); err != nil {
		return fmt.Errorf("移动操作失败: %v", err)
	}
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
		ldapDNEntry.SetText("CN=ldap,OU=Ldap," + domainDN)
	})

	// 设置默认域名和提示文本
	domainEntry.SetText("example.com")
	domainEntry.SetPlaceHolder("请输入LDAP服务器地址，一般是根域名")

	// 创建自定义端口输入框（聚焦时自动填充默认值）
	portEntry := NewCustomPortEntry()
	portEntry.SetPlaceHolder("请输入LDAP服务器端口，一般是389")

	// 创建密码输入框
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("请输入管理员密码")

	// 创建LDAP密码输入框
	ldappasswordEntry := widget.NewPasswordEntry()
	ldappasswordEntry.SetPlaceHolder("请输入LDAP密码")

	// 创建过滤器输入框（用于用户搜索的过滤条件）
	filterDNEntry := widget.NewEntry()
	filterDNEntry.SetPlaceHolder("请输入过滤器")
	filterDNEntry.SetText("(&(objectclass=user)(uid={%s}))") // 默认过滤器模板

	// 创建测试用户输入框
	testUserEntry := widget.NewEntry()
	testUserEntry.SetPlaceHolder("请输入测试用户名")

	// 创建测试密码输入框
	testPasswordEntry := widget.NewPasswordEntry()
	testPasswordEntry.SetPlaceHolder("请输入测试密码")

	// 创建带滚动条的状态显示区域
	statusArea := widget.NewMultiLineEntry()
	statusArea.Disable()                    // 设置为只读模式
	statusArea.Wrapping = fyne.TextWrapWord // 启用自动换行

	// 状态区域布局容器（确保最小显示高度）
	background := canvas.NewRectangle(color.Transparent)
	background.SetMinSize(fyne.NewSize(400, 60)) // 最小尺寸约束
	statusContainer := container.NewStack(
		background,
		container.NewVScroll(statusArea), // 垂直滚动容器
	)

	// 状态更新函数（带时间戳和自动滚动功能）
	updateStatus := func(status string) {
		currentTime := time.Now().Format("15:04:05")      // 获取当前时间
		statusArea.TextStyle = fyne.TextStyle{Bold: true} // 设置粗体显示
		newText := statusArea.Text + currentTime + " " + status + "\n"
		statusArea.SetText(newText)
		statusArea.CursorRow = len(strings.Split(statusArea.Text, "\n")) - 1 // 自动滚动到底部
	}

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
		port := 389 // 默认端口（仅在输入为空时使用）
		if portEntry.Text != "" {
			// 解析用户输入的端口号
			if _, err := fmt.Sscanf(portEntry.Text, "%d", &port); err != nil {
				updateStatus(fmt.Sprintf("错误：无效端口号 %s", portEntry.Text))
				return
			}
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
			dialog.ShowError(fmt.Errorf("admin DN 不能为空"), myWindow)
			updateStatus("错误：请填写admin DN")
			return
		}
		if passwordEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("Admin密码不能为空"), myWindow)
			updateStatus("错误：请填写Admin密码")
			return
		}

		// 解析端口号
		var ldapPort int
		if _, err := fmt.Sscanf(portEntry.Text, "%d", &ldapPort); err != nil || ldapPort < 1 || ldapPort > 65535 {
			dialog.ShowError(fmt.Errorf("无效端口号：%s（必须是1-65535）", portEntry.Text), myWindow)
			updateStatus(fmt.Sprintf("错误：无效端口号 %s", portEntry.Text))
			return
		}

		// 创建LDAP客户端实例
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         ldapPort,
			bindDN:       adminEntry.Text,
			bindPassword: passwordEntry.Text,
			updateFunc:   updateStatus, // 传递状态更新函数
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
		if ldapDNEntry.Text == "" || ldappasswordEntry.Text == "" {
			updateStatus("请输入LDAP用户名和密码")
			return
		}

		// 解析端口号
		port := 389
		if portEntry.Text != "" {
			if _, err := fmt.Sscanf(portEntry.Text, "%d", &port); err != nil {
				dialog.ShowError(fmt.Errorf("无效端口号"), myWindow)
				return
			}
		}

		// 创建LDAP客户端实例（使用管理员凭证）
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       adminEntry.Text,
			bindPassword: passwordEntry.Text,
			updateFunc:   updateStatus, // 传递状态更新函数
		}

		// 测试管理员凭证有效性
		if client.testLDAPService() {
			updateStatus("LDAP管理员验证成功")

			// 从输入的LDAP DN中提取用户名
			userDN := ldapDNEntry.Text
			username := extractUsernameFromDN(userDN)

			// 在整个域中搜索用户
			userExists, foundDN := client.searchUserInDomain(username)

			if userExists {
				updateStatus("用户已存在")

				// 弹出提示框询问是否移动用户
				dialog.ShowConfirm("用户已存在", "是否移动用户？", func(move bool) {
					if move {
						updateStatus("正在移动用户到新的DN")
						// 递归创建目标DN路径
						if err := client.ensureDNExists(userDN); err != nil {
							dialog.ShowError(fmt.Errorf("创建路径失败: %v", err), myWindow)
							return
						}

						// 执行用户移动操作
						if err := client.moveUser(foundDN, userDN); err != nil {
							dialog.ShowError(fmt.Errorf("移动用户失败: %v", err), myWindow)
							updateStatus("用户移动失败")
						} else {
							updateStatus(fmt.Sprintf("用户已成功移动到 %s", userDN))
						}
					} else {
						// 更新LDAP DN为查询到的用户DN
						ldapDNEntry.SetText(foundDN)
					}

					// 弹出提示框询问是否更新用户密码
					dialog.ShowConfirm("更新密码", "是否更新用户密码？", func(updatePassword bool) {
						if updatePassword {
							updateStatus("更新用户密码")
							// TODO: 实现更新密码逻辑
						}
					}, myWindow)
				}, myWindow)
			} else {
				updateStatus("用户不存在，创建新用户")
				// 递归创建用户OU，创建用户，设置密码为LDAP密码
				// TODO: 实现创建用户逻辑
			}
		} else {
			updateStatus("LDAP管理员验证失败")
		}
	})

	// 管理员验证用户按钮回调函数
	adminTestUserButton := widget.NewButton("admin账号验证用户", func() {
		// 输入验证
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			updateStatus("请输入测试用户名和密码")
			return
		}

		// 解析端口号
		port := 389
		if portEntry.Text != "" {
			if _, err := fmt.Sscanf(portEntry.Text, "%d", &port); err != nil {
				dialog.ShowError(fmt.Errorf("无效端口号"), myWindow)
				return
			}
		}

		// 创建LDAP客户端实例
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       adminEntry.Text,
			bindPassword: passwordEntry.Text,
			updateFunc:   updateStatus, // 传递状态更新函数
		}

		// 执行用户认证测试
		if client.testUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text) {
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

		// 解析端口号
		port := 389
		if portEntry.Text != "" {
			if _, err := fmt.Sscanf(portEntry.Text, "%d", &port); err != nil {
				dialog.ShowError(fmt.Errorf("无效端口号"), myWindow)
				return
			}
		}

		// 创建LDAP客户端实例（使用LDAP账号凭证）
		client := LDAPClient{
			host:         domainEntry.Text,
			port:         port,
			bindDN:       ldapDNEntry.Text,
			bindPassword: ldappasswordEntry.Text,
			updateFunc:   updateStatus, // 传递状态更新函数
		}

		// 执行用户认证测试
		if client.testUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text) {
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
		container.NewBorder(nil, nil, makeLabel("服务器端口:"), portTestButton,
			portEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Admin DN:"), nil,
			adminEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Admin密码:"), adminTestButton,
			passwordEntry,
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
			filterDNEntry,
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
