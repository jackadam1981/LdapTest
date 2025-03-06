package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"LdapTest/ldap"
	"LdapTest/ui"
)

func main() {
	// 设置中文字体路径（仅Windows系统）
	os.Setenv("FYNE_FONT", "C:\\Windows\\Fonts\\SIMYOU.TTF")

	// 创建应用程序实例
	myApp := app.New()
	// 应用自定义主题
	myApp.Settings().SetTheme(ui.NewMyTheme())
	// 创建主窗口
	myWindow := myApp.NewWindow("LDAP Client")

	// 创建状态区域
	statusArea := widget.NewMultiLineEntry()
	statusArea.Disable()                    // 设置为只读模式
	statusArea.Wrapping = fyne.TextWrapWord // 启用自动换行

	// 状态容器 - 移除标题，直接使用状态区域
	statusContainer := container.NewVScroll(statusArea)

	// 定义状态更新函数
	updateStatus := func(status string) {
		currentTime := time.Now().Format("15:04:05")      // 获取当前时间
		statusArea.TextStyle = fyne.TextStyle{Bold: true} // 设置粗体显示
		newText := statusArea.Text + currentTime + " " + status + "\n"
		statusArea.SetText(newText)
		statusArea.CursorRow = len(strings.Split(statusArea.Text, "\n")) - 1 // 自动滚动到底部
	}

	// 创建输入框
	var domainEntry *ui.CustomDomainEntry
	var adminEntry *widget.Entry
	var passwordEntry *widget.Entry
	var ldapPasswordEntry *widget.Entry
	var ldapDNEntry *widget.Entry
	var ldapGroupEntry *widget.SelectEntry
	var searchDNEntry *widget.Entry
	var testUserEntry *widget.Entry
	var testPasswordEntry *widget.Entry

	// 初始化输入框
	adminEntry = widget.NewEntry()
	adminEntry.SetPlaceHolder("请输入管理员DN")

	passwordEntry = widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("请输入管理员密码")

	ldapPasswordEntry = widget.NewPasswordEntry()
	ldapPasswordEntry.SetPlaceHolder("请输入LDAP密码")

	ldapDNEntry = widget.NewEntry()
	ldapDNEntry.SetPlaceHolder("请输入LDAP DN")

	// 创建LDAP权限组输入框（既可以输入又可以选择）
	ldapGroupEntry = widget.NewSelectEntry([]string{""})
	ldapGroupEntry.SetPlaceHolder("请输入或选择权限组")

	searchDNEntry = widget.NewEntry()
	searchDNEntry.SetPlaceHolder("CN=Users,DC=example,DC=com")

	testUserEntry = widget.NewEntry()
	testUserEntry.SetPlaceHolder("请输入测试用户名")

	testPasswordEntry = widget.NewPasswordEntry()
	testPasswordEntry.SetPlaceHolder("请输入测试密码")

	domainEntry = ui.NewCustomDomainEntry(func() {
		if domainEntry.Text == "" {
			return
		}
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
	})
	domainEntry.SetPlaceHolder("example.com")

	portEntry := ui.NewCustomPortEntry()

	// SSL支持标志
	isSSLEnabled := false

	// 创建按钮
	pingButton := widget.NewButton("连接测试", func() {
		updateStatus(fmt.Sprintf("正在Ping %s...", domainEntry.Text))

		// 实现Ping功能
		host := domainEntry.Text
		if host == "" {
			updateStatus("请输入服务器地址")
			return
		}

		// 创建ping命令（Windows用-n，Linux/macOS用-c）
		// 使用cmd.exe并设置输出为UTF-8编码
		cmd := exec.Command("cmd", "/c", "chcp 65001 >nul && ping -n 4 "+host)
		output, err := cmd.CombinedOutput()
		if err != nil {
			updateStatus(fmt.Sprintf("ping命令执行失败: %v", err))
			return
		}

		// 解析ping输出，提取平均时间
		outputStr := string(output)
		log.Printf("Ping输出: %s", outputStr) // 记录完整输出用于调试

		// 在Windows中，平均延迟信息位于包含"平均"的行中
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			// 尝试匹配中英文结果
			if strings.Contains(line, "平均") || strings.Contains(line, "Average") {
				updateStatus(fmt.Sprintf("ping测试完成，结果: %s", strings.TrimSpace(line)))
				return
			}
		}

		// 如果没有找到平均时间行，至少显示最后一行结果
		if len(lines) > 0 {
			lastLine := lines[len(lines)-1]
			if lastLine == "" && len(lines) > 1 {
				lastLine = lines[len(lines)-2]
			}
			updateStatus(fmt.Sprintf("ping测试完成: %s", strings.TrimSpace(lastLine)))
		} else {
			updateStatus("ping测试完成，但无法解析结果")
		}
	})

	portTestButton := widget.NewButton("测试端口", func() {
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}

		client := ldap.LDAPClient{
			Host:       domainEntry.Text,
			Port:       port,
			UpdateFunc: updateStatus,
			UseTLS:     isSSLEnabled,
		}

		if client.IsPortOpen() {
			updateStatus(fmt.Sprintf("端口 %d 已开放", port))
		} else {
			updateStatus(fmt.Sprintf("端口 %d 未开放", port))
		}
	})

	adminTestButton := widget.NewButton("测试管理员", func() {
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}

		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			UseTLS:       isSSLEnabled,
		}

		// 分步骤测试
		if client.IsPortOpen() {
			serviceType := "LDAP"
			if client.UseTLS {
				serviceType = "LDAPS"
			}
			updateStatus(fmt.Sprintf("%s 端口正常打开", serviceType))

			if client.TestLDAPService() {
				updateStatus(fmt.Sprintf("%s 服务正常", serviceType))
			} else {
				updateStatus(fmt.Sprintf("%s 服务异常", serviceType))
			}
		} else {
			serviceType := "LDAP"
			if client.UseTLS {
				serviceType = "LDAPS"
			}
			updateStatus(fmt.Sprintf("%s 端口未开放", serviceType))
		}
	})

	// 创建LDAP用户按钮
	createLdapButton := widget.NewButton("创建LDAP用户", func() {
		// 从DN中提取用户名
		userDN := ldapDNEntry.Text
		parts := strings.Split(userDN, ",")
		if len(parts) == 0 || !strings.HasPrefix(strings.ToLower(parts[0]), "cn=") {
			updateStatus("无效的用户DN格式")
			return
		}
		userName := strings.TrimPrefix(parts[0], "CN=")

		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}

		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			UseTLS:       isSSLEnabled,
		}

		// 先检查端口连通性
		if !client.IsPortOpen() {
			updateStatus(fmt.Sprintf("端口 %d 未开放", port))
			return
		}

		// 验证管理员凭证
		if !client.TestLDAPService() {
			dialog.ShowError(fmt.Errorf("管理员认证失败\n可能原因：\n1. 密码错误\n2. DN格式错误\n3. 权限不足"), myWindow)
			updateStatus("管理员凭证验证失败")
			return
		}

		// 检查用户是否已存在
		found, foundUserDN := client.SearchUserInDomain(userName)
		if found {
			// 用户已存在，询问是否移动
			dialog.ShowConfirm("用户已存在",
				fmt.Sprintf("发现同名用户：\n%s\n\n当前输入位置：\n%s\n\n是否要移动用户？",
					foundUserDN,
					userDN),
				func(move bool) {
					if move {
						updateStatus(fmt.Sprintf("正在移动用户 %s -> %s", foundUserDN, userDN))
						if err := client.MoveUser(foundUserDN, userDN); err != nil {
							dialog.ShowError(fmt.Errorf("移动失败: %v", err), myWindow)
							updateStatus("用户移动失败")
						} else {
							updateStatus("用户移动成功")
							ldapDNEntry.SetText(userDN) // 保持新位置
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
		parentDN := strings.SplitN(userDN, ",", 2)[1]
		if err := client.EnsureDNExists(parentDN); err != nil {
			dialog.ShowError(fmt.Errorf("创建路径失败: %v", err), myWindow)
			updateStatus("创建用户失败：无法创建目标路径")
			return
		}

		// 确保连接依然有效
		conn, err := client.GetConnection()
		if err != nil {
			updateStatus(fmt.Sprintf("创建用户时LDAP连接失败: %v", err))
			return
		}

		// 根据SSL状态选择创建用户的函数
		if isSSLEnabled {
			// SSL模式：创建启用账号并设置密码
			err := ldap.CreateUserWithSSL(conn, &client, userDN, userName, ldapPasswordEntry.Text, client.Host, myWindow, updateStatus)
			if err != nil {
				dialog.ShowError(err, myWindow)
				updateStatus(fmt.Sprintf("创建用户失败: %v", err))
				return
			}
		} else {
			// 非SSL模式：创建禁用账号
			err := ldap.CreateUserWithoutSSL(conn, userDN, userName, client.Host, updateStatus)
			if err != nil {
				dialog.ShowError(err, myWindow)
				updateStatus(fmt.Sprintf("创建用户失败: %v", err))
				return
			}
		}
	})

	// 检查权限组按钮
	groupButton := widget.NewButton("检查权限组", func() {
		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}

		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			UseTLS:       isSSLEnabled,
		}

		// 先检查端口连通性
		if !client.IsPortOpen() {
			updateStatus(fmt.Sprintf("端口 %d 未开放", port))
			return
		}

		// 验证管理员凭证
		if !client.TestLDAPService() {
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

		// 检查组是否已存在
		found, foundGroupDN := client.SearchGroup(groupName, searchDNEntry.Text)
		if found {
			// 当DN完全相同时（不区分大小写）
			if strings.EqualFold(strings.ToLower(foundGroupDN), strings.ToLower(ldapGroupEntry.Text)) {
				// 提示是否需要重新授权
				dialog.ShowConfirm("组已存在",
					fmt.Sprintf("组已存在且位置正确：\n%s\n\n是否要重新授权该组？", foundGroupDN),
					func(reauth bool) {
						if reauth {
							updateStatus("开始重新授权组权限...")

							// 获取有效连接
							_, err := client.GetConnection()
							if err != nil {
								dialog.ShowError(fmt.Errorf("连接失败: %v", err), myWindow)
								updateStatus("重新授权失败：连接错误")
								return
							}

							// 创建修改请求
							attributes := map[string][]string{
								"groupType":   {"-2147483646"},
								"description": {"LDAP Authentication Group"},
							}
							if err := client.ModifyGroup(ldapGroupEntry.Text, attributes); err != nil {
								dialog.ShowError(fmt.Errorf("重新授权失败: %v", err), myWindow)
								updateStatus("组重新授权失败")
							} else {
								updateStatus(fmt.Sprintf("组重新授权成功：%s", ldapGroupEntry.Text))
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
						if err := client.MoveUser(foundGroupDN, ldapGroupEntry.Text); err != nil {
							dialog.ShowError(fmt.Errorf("移动失败: %v", err), myWindow)
							updateStatus("组移动失败")
						} else {
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

		// 创建新组
		if err := client.CreateGroup(ldapGroupEntry.Text, groupName); err != nil {
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
			names = append(names, "(Select one)")
			for _, f := range ldap.CommonFilters() {
				names = append(names, f.Name)
			}
			return names
		}(),
		nil,
	)
	filterSelect.SetSelected("(Select one)") // 设置默认选项

	// 创建过滤器描述标签
	filterDescription := widget.NewEntry()
	filterDescription.Disable() // 设置为只读，但允许选择和复制
	filterDescription.Hide()    // 初始隐藏描述

	// 更新过滤器描述的函数
	updateFilterDescription := func(filterName string) {
		if filterName == "(Select one)" {
			filterDescription.Hide()
			return
		}

		filterDescription.Show()
		for _, f := range ldap.CommonFilters() {
			if f.Name == filterName {
				filterDescription.Enable() // 临时启用以设置文本
				filterDescription.SetText(f.Pattern)
				filterDescription.Disable() // 重新禁用以保持只读状态
				break
			}
		}
	}

	// 设置选择框回调
	filterSelect.OnChanged = updateFilterDescription
	updateFilterDescription("(Select one)") // 初始化描述

	// 管理员验证用户按钮
	adminTestUserButton := widget.NewButton("admin账号验证用户", func() {
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			updateStatus("请输入测试用户名和密码")
			return
		}

		// 获取选定的过滤器模式
		var filterPattern string
		for _, f := range ldap.CommonFilters() {
			if f.Name == filterSelect.Selected {
				filterPattern = f.Pattern
				break
			}
		}

		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}
		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			UseTLS:       isSSLEnabled,
		}

		updateStatus(fmt.Sprintf("使用 %s 过滤器开始验证用户...", filterSelect.Selected))
		if client.TestUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, filterPattern) {
			updateStatus("测试用户验证成功")
		} else {
			updateStatus("测试用户验证失败")
		}
	})

	// LDAP账号验证用户按钮
	ldapTestUserButton := widget.NewButton("LDAP账号验证用户", func() {
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			updateStatus("请输入测试用户名和密码")
			return
		}

		// 获取选定的过滤器模式
		var filterPattern string
		for _, f := range ldap.CommonFilters() {
			if f.Name == filterSelect.Selected {
				filterPattern = f.Pattern
				break
			}
		}

		port, err := portEntry.GetPort()
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}
		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       ldapDNEntry.Text,
			BindPassword: ldapPasswordEntry.Text,
			UpdateFunc:   updateStatus,
			UseTLS:       isSSLEnabled,
		}

		updateStatus(fmt.Sprintf("使用 %s 过滤器开始验证用户...", filterSelect.Selected))
		if client.TestUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, filterPattern) {
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
				isSSLEnabled = checked // 更新SSL状态
				if checked {
					portEntry.SetDefaultPort(true)                         // SSL端口
					ldapPasswordEntry.SetPlaceHolder("SSL模式下创建的用户是可以直接用的") // 更新占位符提示
				} else {
					portEntry.SetDefaultPort(false)                          // 标准端口
					ldapPasswordEntry.SetPlaceHolder("非SSL模式创建的用户是没有密码停用的）") // 更新占位符提示
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
			ldapPasswordEntry,
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

	// 设置窗口关闭事件，确保所有LDAP连接都被正确关闭
	myWindow.SetOnClosed(func() {
		log.Println("应用程序正在关闭，清理资源...")
	})

	myWindow.ShowAndRun()
}
