package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"LdapTest/ldap"
	"LdapTest/logger"
	"LdapTest/ui"
)

// 全局变量，用于控制调试模式
var debugMode bool
var appLogger *logger.Logger

// 处理已存在用户的情况
func handleExistingUser(client *ldap.LDAPClient, userDN string, password string, groupDN string, isSSL bool, window fyne.Window) {
	appLogger.Info("处理已存在用户，DN: %s, SSL模式: %v", userDN, isSSL)
	if isSSL {
		dialog.ShowConfirm("用户已存在",
			fmt.Sprintf("用户已存在且位置相同：\n%s\n\n是否要更新用户密码？", userDN),
			func(updatePassword bool) {
				if updatePassword {
					appLogger.Info("开始更新用户密码...")
					if err := client.UpdateUserPassword(userDN, password); err != nil {
						appLogger.Error("密码更新失败：%v", err)
						dialog.ShowError(err, window)
						return
					}
					appLogger.Info("用户密码更新成功")
				} else {
					appLogger.Info("保持用户密码不变：%s", userDN)
				}
				promptForGroupMembership(client, userDN, groupDN, window)
			}, window)
	} else {
		dialog.ShowConfirm("用户已存在",
			fmt.Sprintf("用户已存在且位置相同：\n%s\n\n非SSL模式下无法更新密码，是否继续？", userDN),
			func(confirmed bool) {
				if confirmed {
					appLogger.Debug("用户确认继续操作")
					appLogger.Info("用户已存在：%s", userDN)
					promptForGroupMembership(client, userDN, groupDN, window)
				} else {
					appLogger.Debug("用户取消操作")
					appLogger.Info("操作已取消")
				}
			}, window)
	}
}

// 处理用户移动的情况
func handleUserMove(client *ldap.LDAPClient, currentDN string, targetDN string, password string, groupDN string, isSSL bool, window fyne.Window) {
	appLogger.Debug("处理用户移动，当前DN: %s, 目标DN: %s, SSL模式: %v", currentDN, targetDN, isSSL)
	dialog.ShowConfirm("用户已存在",
		fmt.Sprintf("发现同名用户：\n%s\n\n当前输入位置：\n%s\n\n是否要移动用户？",
			currentDN,
			targetDN),
		func(move bool) {
			if move {
				appLogger.Debug("用户确认移动操作")
				appLogger.Info("正在移动用户 %s -> %s", currentDN, targetDN)
				if err := client.MoveUserToNewLocation(currentDN, targetDN); err != nil {
					appLogger.Error("用户移动失败：%v", err)
					dialog.ShowError(err, window)
					return
				}
				appLogger.Info("用户移动成功")
				promptForGroupMembership(client, targetDN, groupDN, window)

				if isSSL {
					appLogger.Debug("SSL模式下，准备更新密码")
					promptForPasswordUpdate(client, targetDN, password, window)
				}
			} else {
				appLogger.Debug("用户取消移动操作，使用现有位置")
				appLogger.Info("已使用现有用户位置：%s", currentDN)
				promptForGroupMembership(client, currentDN, groupDN, window)
			}
		}, window)
}

// 提示是否加入LDAP组
func promptForGroupMembership(client *ldap.LDAPClient, userDN string, groupDN string, window fyne.Window) {
	appLogger.Debug("提示加入LDAP组，用户DN: %s, 组DN: %s", userDN, groupDN)
	dialog.ShowConfirm("添加到组",
		fmt.Sprintf("是否要将用户加入LDAP组？\n用户: %s\n组: %s", userDN, groupDN),
		func(addToGroup bool) {
			if addToGroup {
				appLogger.Debug("用户确认加入组操作")
				appLogger.Info("正在将用户添加到组 %s", groupDN)
				if err := client.HandleGroupMembership(userDN, groupDN); err != nil {
					appLogger.Error("添加用户到组失败：%v", err)
					dialog.ShowError(err, window)
					return
				}
				appLogger.Info("用户成功添加到组")
			} else {
				appLogger.Debug("用户取消加入组操作")
			}
		}, window)
}

// 提示是否更新密码
func promptForPasswordUpdate(client *ldap.LDAPClient, userDN string, password string, window fyne.Window) {
	appLogger.Debug("提示更新密码，用户DN: %s", userDN)
	dialog.ShowConfirm("更新密码",
		"是否要更新用户密码？",
		func(updatePassword bool) {
			if updatePassword {
				appLogger.Debug("用户确认更新密码")
				appLogger.Info("开始更新用户密码...")
				if err := client.UpdateUserPassword(userDN, password); err != nil {
					appLogger.Error("密码更新失败：%v", err)
					dialog.ShowError(err, window)
					return
				}
				appLogger.Info("用户密码更新成功")
			} else {
				appLogger.Debug("用户取消密码更新")
			}
		}, window)
}

func main() {
	// 解析命令行参数
	flag.BoolVar(&debugMode, "debug", false, "启用调试模式")
	flag.Parse()

	// 设置中文字体路径（仅Windows系统）
	os.Setenv("FYNE_FONT", "C:\\Windows\\Fonts\\SIMYOU.TTF")

	// 创建应用程序实例
	myApp := app.New()
	// 应用自定义主题
	myApp.Settings().SetTheme(ui.NewMyTheme())
	// 创建主窗口
	myWindow := myApp.NewWindow("LDAP Client")

	// 创建状态区域
	statusArea, statusContainer := logger.CreateStatusArea()
	updateStatus := logger.CreateUpdateStatusFunc(statusArea, statusContainer)

	// 初始化日志记录器
	appLogger = logger.New(debugMode, updateStatus)

	// 记录应用程序启动信息
	appLogger.Info("应用程序启动，调试模式：%v", debugMode)

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
			appLogger.Debug("域名为空，跳过自动填充")
			return
		}
		appLogger.Debug("处理域名：%s", domainEntry.Text)
		domainParts := strings.Split(domainEntry.Text, ".")
		var dnParts []string
		for _, part := range domainParts {
			dnParts = append(dnParts, "DC="+part)
		}
		domainDN := strings.Join(dnParts, ",")
		appLogger.Debug("生成域DN：%s", domainDN)

		// 自动生成管理员DN和搜索DN
		adminDN := "CN=Administrator,CN=Users," + domainDN
		appLogger.Debug("设置管理员DN：%s", adminDN)
		adminEntry.SetText(adminDN)

		appLogger.Debug("设置搜索DN：%s", domainDN)
		searchDNEntry.SetText(domainDN)

		ldapUserDN := "CN=Ldap,CN=Ldap," + domainDN
		appLogger.Debug("设置LDAP用户DN：%s", ldapUserDN)
		ldapDNEntry.SetText(ldapUserDN)

		ldapGroupDN := "CN=LdapGroup,CN=Users," + domainDN
		appLogger.Debug("设置LDAP组DN：%s", ldapGroupDN)
		ldapGroupEntry.SetText(ldapGroupDN)
	})
	domainEntry.SetPlaceHolder("example.com")

	portEntry := ui.NewCustomPortEntry()

	// SSL支持标志
	isSSLEnabled := false

	// 创建按钮
	pingButton := widget.NewButton("连接测试", func() {
		appLogger.Debug("开始Ping测试")
		appLogger.Debug("正在Ping %s...", domainEntry.Text)

		// 实现Ping功能
		host := domainEntry.Text
		if host == "" {
			appLogger.Warn("服务器地址为空")
			appLogger.Error("请输入服务器地址")
			return
		}
		appLogger.Debug("Ping目标主机：%s", host)

		// 创建ping命令（Windows用-n，Linux/macOS用-c）
		// 使用cmd.exe并设置输出为UTF-8编码
		cmd := exec.Command("cmd", "/c", "chcp 65001 >nul && ping -n 4 "+host)
		appLogger.Debug("执行命令：%s", cmd.String())
		output, err := cmd.CombinedOutput()
		if err != nil {
			appLogger.Error("ping命令执行失败：%v", err)
			return
		}

		// 解析ping输出，提取平均时间
		outputStr := string(output)
		appLogger.Debug("Ping输出：\n%s", outputStr)

		// 在Windows中，平均延迟信息位于包含"平均"的行中
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			// 尝试匹配中英文结果
			if strings.Contains(line, "平均") || strings.Contains(line, "Average") {
				appLogger.Debug("找到平均延迟信息：%s", strings.TrimSpace(line))
				appLogger.Info("ping测试完成，结果: %s", strings.TrimSpace(line))
				return
			}
		}

		// 如果没有找到平均时间行，至少显示最后一行结果
		if len(lines) > 0 {
			lastLine := lines[len(lines)-1]
			if lastLine == "" && len(lines) > 1 {
				lastLine = lines[len(lines)-2]
			}
			appLogger.Debug("未找到平均延迟信息，使用最后一行：%s", strings.TrimSpace(lastLine))
			appLogger.Info("ping测试完成: %s", strings.TrimSpace(lastLine))
		} else {
			appLogger.Debug("ping输出为空")
			appLogger.Warn("ping测试完成，但无法解析结果")
		}
	})

	portTestButton := widget.NewButton("测试服务", func() {
		appLogger.Debug("开始端口和服务测试")
		port, err := portEntry.GetPort()
		if err != nil {
			appLogger.Error("获取端口失败：%v", err)
			dialog.ShowError(err, myWindow)
			return
		}

		protocol := "LDAP"
		if isSSLEnabled {
			protocol = "LDAPS"
		}

		appLogger.Info("开始测试 %s 服务，端口：%d", protocol, port)

		// 创建 LDAP 客户端
		client := ldap.LDAPClient{
			Host:       domainEntry.Text,
			Port:       port,
			UpdateFunc: updateStatus,
			Logger:     appLogger,
			UseTLS:     isSSLEnabled,
			DebugMode:  debugMode,
		}
		appLogger.Debug("创建LDAP客户端，目标主机：%s", domainEntry.Text)

		// 第一步：测试端口
		appLogger.Debug("第1步：测试 %s 端口 %d 是否开放", protocol, port)
		if client.IsPortOpen() {
			appLogger.Info("√ %s 端口 %d 已开放", protocol, port)

			// 第二步：测试服务
			appLogger.Debug("第2步：测试 %s 服务连接状态", protocol)

			conn, err := client.TestServiceConnection()
			if err != nil {
				appLogger.Warn("× %s 服务连接失败: %v", protocol, err)
				appLogger.Info("服务测试结果: %s 端口已开放，但服务连接异常", protocol)
			} else {
				conn.Close() // 确保连接关闭
				appLogger.Info("√ %s 服务连接成功", protocol)
				appLogger.Info("服务测试结果: %s 端口已开放，服务正常运行", protocol)
			}
		} else {
			appLogger.Warn("× %s 端口 %d 未开放", protocol, port)
			appLogger.Info("服务测试结果: %s 端口未开放，无法测试服务", protocol)
		}
	})

	adminTestButton := widget.NewButton("测试管理员", func() {
		appLogger.Debug("开始测试管理员凭证")

		// 验证管理员密码不为空
		if adminEntry.Text == "" || passwordEntry.Text == "" {
			appLogger.Error("验证失败：管理员DN或密码为空")
			dialog.ShowError(fmt.Errorf("管理员DN和密码不能为空"), myWindow)
			return
		}

		// 验证服务器地址不为空
		if domainEntry.Text == "" {
			appLogger.Error("验证失败：服务器地址为空")
			dialog.ShowError(fmt.Errorf("请输入服务器地址"), myWindow)
			return
		}

		port, err := portEntry.GetPort()
		if err != nil {
			appLogger.Error("获取端口失败：%v", err)
			dialog.ShowError(err, myWindow)
			return
		}

		protocol := "LDAP"
		if isSSLEnabled {
			protocol = "LDAPS"
		}

		appLogger.Debug("测试 %s 服务，端口：%d", protocol, port)

		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			Logger:       appLogger,
			UseTLS:       isSSLEnabled,
			DebugMode:    debugMode,
		}
		appLogger.Debug("创建LDAP客户端，目标主机：%s", domainEntry.Text)

		// 分步骤测试
		if client.IsPortOpen() {
			appLogger.Debug("%s 端口 %d 已开放", protocol, port)

			if client.TestLDAPService() {
				appLogger.Info("%s 服务正常运行，管理员认证成功", protocol)
			} else {
				appLogger.Warn("%s 服务连接异常或管理员认证失败", protocol)
			}
		} else {
			appLogger.Warn("%s 端口 %d 未开放", protocol, port)
		}
	})

	// 创建LDAP用户按钮
	createLdapButton := widget.NewButton("创建LDAP用户", func() {
		appLogger.Debug("开始创建LDAP用户操作")

		// 输入验证
		if ldapDNEntry.Text == "" {
			appLogger.Error("验证失败：LDAP DN不能为空")
			dialog.ShowError(fmt.Errorf("LDAP DN不能为空"), myWindow)
			return
		}
		if isSSLEnabled && ldapPasswordEntry.Text == "" {
			appLogger.Error("验证失败：SSL模式下密码不能为空")
			dialog.ShowError(fmt.Errorf("SSL模式下LDAP密码不能为空"), myWindow)
			return
		}

		port, err := portEntry.GetPort()
		if err != nil {
			appLogger.Error("获取端口失败：%v", err)
			dialog.ShowError(err, myWindow)
			return
		}
		appLogger.Debug("使用端口：%d，SSL模式：%v", port, isSSLEnabled)

		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			Logger:       appLogger,
			UseTLS:       isSSLEnabled,
			DebugMode:    debugMode,
		}
		appLogger.Debug("创建LDAP客户端，目标主机：%s", domainEntry.Text)

		// 先检查端口连通性
		if !client.IsPortOpen() {
			appLogger.Warn("端口 %d 未开放", port)
			return
		}
		appLogger.Debug("端口连通性检查通过")

		// 验证管理员凭证
		if !client.TestLDAPService() {
			appLogger.Error("管理员认证失败，BindDN: %s", adminEntry.Text)
			dialog.ShowError(fmt.Errorf("管理员认证失败\n可能原因：\n1. 密码错误\n2. DN格式错误\n3. 权限不足"), myWindow)
			return
		}
		appLogger.Info("管理员认证成功")

		// 从输入的DN中提取CN
		enteredCN := strings.SplitN(ldapDNEntry.Text, ",", 2)[0]
		if !strings.HasPrefix(enteredCN, "CN=") {
			appLogger.Error("DN格式无效：%s", ldapDNEntry.Text)
			return
		}
		userName := strings.TrimPrefix(enteredCN, "CN=")
		appLogger.Debug("提取用户名：%s", userName)

		// 检查用户是否存在
		found, foundUserDN := client.SearchUser(userName, searchDNEntry.Text)
		if found {
			appLogger.Debug("发现已存在用户，DN: %s", foundUserDN)
			// 当DN完全相同时（不区分大小写）
			if strings.EqualFold(strings.ToLower(foundUserDN), strings.ToLower(ldapDNEntry.Text)) {
				appLogger.Debug("用户位置相同，处理已存在用户情况")
				handleExistingUser(&client, foundUserDN, ldapPasswordEntry.Text, ldapGroupEntry.Text, isSSLEnabled, myWindow)
				return
			}

			// 用户存在但位置不同，询问是否移动
			appLogger.Debug("用户存在但位置不同，当前位置：%s，目标位置：%s", foundUserDN, ldapDNEntry.Text)
			handleUserMove(&client, foundUserDN, ldapDNEntry.Text, ldapPasswordEntry.Text, ldapGroupEntry.Text, isSSLEnabled, myWindow)
			return
		}

		// 不存在则创建新用户
		appLogger.Info("未找到已存在用户，开始创建新用户")
		err = client.CreateOrUpdateUser(ldapDNEntry.Text, userName, ldapPasswordEntry.Text, isSSLEnabled)
		if err != nil {
			appLogger.Error("创建用户失败：%v", err)
			// 检查是否是用户已存在的错误
			if strings.Contains(err.Error(), "Entry Already Exists") {
				dialog.ShowError(fmt.Errorf("创建用户失败：用户已存在\n请检查搜索范围是否正确"), myWindow)
			} else {
				dialog.ShowError(fmt.Errorf("创建用户失败：%s", err), myWindow)
			}
			return
		}
		appLogger.Info("用户创建成功")

		// 询问是否要将用户加入LDAP组
		appLogger.Debug("准备处理组成员关系，组DN: %s", ldapGroupEntry.Text)
		promptForGroupMembership(&client, ldapDNEntry.Text, ldapGroupEntry.Text, myWindow)
	})

	// 检查权限组按钮
	groupButton := widget.NewButton("检查权限组", func() {
		appLogger.Debug("开始检查权限组操作")
		port, err := portEntry.GetPort()
		if err != nil {
			appLogger.Error("获取端口失败：%v", err)
			dialog.ShowError(err, myWindow)
			return
		}
		appLogger.Debug("使用端口：%d，SSL模式：%v", port, isSSLEnabled)

		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			Logger:       appLogger,
			UseTLS:       isSSLEnabled,
			DebugMode:    debugMode,
		}
		appLogger.Debug("创建LDAP客户端，目标主机：%s", domainEntry.Text)

		// 先检查端口连通性
		if !client.IsPortOpen() {
			appLogger.Warn("端口 %d 未开放", port)
			return
		}
		appLogger.Debug("端口连通性检查通过")

		// 验证管理员凭证
		if !client.TestLDAPService() {
			appLogger.Error("管理员认证失败，BindDN: %s", adminEntry.Text)
			dialog.ShowError(fmt.Errorf("管理员认证失败\n可能原因：\n1. 密码错误\n2. DN格式错误\n3. 权限不足"), myWindow)
			return
		}
		appLogger.Info("管理员认证成功")

		// 从输入的组DN中提取CN
		enteredGroupCN := strings.SplitN(ldapGroupEntry.Text, ",", 2)[0]
		if !strings.HasPrefix(enteredGroupCN, "CN=") {
			appLogger.Error("组DN格式无效：%s", ldapGroupEntry.Text)
			return
		}
		groupName := strings.TrimPrefix(enteredGroupCN, "CN=")
		appLogger.Debug("提取组名：%s", groupName)

		// 检查组是否已存在
		found, foundGroupDN := client.SearchGroup(groupName, searchDNEntry.Text)
		if found {
			appLogger.Debug("发现已存在组，DN: %s", foundGroupDN)
			// 当DN完全相同时（不区分大小写）
			if strings.EqualFold(strings.ToLower(foundGroupDN), strings.ToLower(ldapGroupEntry.Text)) {
				// 提示是否需要重新授权
				dialog.ShowConfirm("组已存在",
					fmt.Sprintf("组已存在且位置正确：\n%s\n\n是否要重新授权该组？", foundGroupDN),
					func(reauth bool) {
						if reauth {
							appLogger.Debug("用户确认重新授权组：%s", foundGroupDN)
							appLogger.Info("开始重新授权组权限...")

							// 获取有效连接
							_, err := client.GetConnection()
							if err != nil {
								appLogger.Error("获取连接失败：%v", err)
								dialog.ShowError(fmt.Errorf("连接失败: %v", err), myWindow)
								return
							}
							appLogger.Debug("成功获取LDAP连接")

							// 创建修改请求
							attributes := map[string][]string{
								"groupType":   {"-2147483646"},
								"description": {"LDAP Authentication Group"},
							}
							appLogger.Debug("准备修改组属性：%v", attributes)
							if err := client.ModifyGroup(ldapGroupEntry.Text, attributes); err != nil {
								appLogger.Error("修改组属性失败：%v", err)
								dialog.ShowError(fmt.Errorf("重新授权失败: %s", ldap.ParseLDAPError(err)), myWindow)
								return
							}

							// 配置SSO所需的ACL权限
							appLogger.Debug("开始配置组的SSO权限")
							if err := client.ConfigureGroupForSSO(ldapGroupEntry.Text, searchDNEntry.Text); err != nil {
								appLogger.Error("配置SSO权限失败：%v", err)
								dialog.ShowError(fmt.Errorf("SSO权限配置失败: %s", ldap.ParseLDAPError(err)), myWindow)
								return
							}
							appLogger.Info("组属性修改成功")
							appLogger.Info("SSO权限配置成功：%s", ldapGroupEntry.Text)
						} else {
							appLogger.Debug("用户取消重新授权组")
							appLogger.Info("保持现有组权限不变：%s", foundGroupDN)
						}
					}, myWindow)
				appLogger.Debug("标准化组DN显示格式：%s", foundGroupDN)
				ldapGroupEntry.SetText(foundGroupDN)
				return
			}

			// 原有的移动组逻辑保持不变
			dialog.ShowConfirm("组已存在",
				fmt.Sprintf("发现同名组：\n%s\n\n当前输入位置：\n%s\n\n是否要移动组？",
					foundGroupDN,
					ldapGroupEntry.Text),
				func(move bool) {
					if move {
						appLogger.Debug("用户确认移动组，从 %s 到 %s", foundGroupDN, ldapGroupEntry.Text)
						appLogger.Info("正在移动组 %s -> %s", foundGroupDN, ldapGroupEntry.Text)
						if err := client.MoveUser(foundGroupDN, ldapGroupEntry.Text); err != nil {
							appLogger.Error("移动组失败：%v", err)
							dialog.ShowError(fmt.Errorf("移动失败: %s", ldap.ParseLDAPError(err)), myWindow)
							return
						}
						appLogger.Info("组移动成功")
						appLogger.Debug("更新组DN显示为新位置：%s", ldapGroupEntry.Text)
						ldapGroupEntry.SetText(ldapGroupEntry.Text)
					} else {
						appLogger.Debug("用户取消移动组，使用现有位置：%s", foundGroupDN)
						ldapGroupEntry.SetText(foundGroupDN)
						appLogger.Info("已使用现有组位置：%s", foundGroupDN)
					}
				}, myWindow)
			return
		}

		// 不存在则继续创建流程
		appLogger.Info("未找到同名组，准备创建新组：%s", ldapGroupEntry.Text)

		// 创建新组
		if err := client.CreateGroup(ldapGroupEntry.Text, groupName); err != nil {
			appLogger.Error("创建组失败：%v", err)
			dialog.ShowError(fmt.Errorf("创建组失败: %s", ldap.ParseLDAPError(err)), myWindow)
			return
		}

		appLogger.Info("成功创建新组：%s", ldapGroupEntry.Text)
	})

	// 创建过滤器选择框
	appLogger.Debug("初始化过滤器选择框")
	filterList := func() []string {
		var names []string
		names = append(names, "(Select one)")
		for _, f := range ldap.CommonFilters() {
			names = append(names, f.Name)
		}
		appLogger.Debug("加载过滤器列表：%v", names)
		return names
	}()

	// 创建过滤器描述标签
	appLogger.Debug("创建过滤器描述标签")
	filterDescLabel := widget.NewEntry()
	filterDescLabel.Disable()
	filterDescLabel.Hide()

	// 更新过滤器描述的函数
	updateFilterDescription := func(filterName string) {
		appLogger.Debug("更新过滤器描述，选择：%s", filterName)
		if filterName == "(Select one)" {
			appLogger.Debug("隐藏过滤器描述")
			filterDescLabel.Hide()
			return
		}

		filterDescLabel.Show()
		for _, f := range ldap.CommonFilters() {
			if f.Name == filterName {
				appLogger.Debug("设置过滤器描述：%s", f.Pattern)
				filterDescLabel.Enable() // 临时启用以设置文本
				filterDescLabel.SetText(f.Pattern)
				filterDescLabel.Disable() // 重新禁用以保持只读状态
				break
			}
		}
	}

	// 过滤器选择框
	filterSelect := widget.NewSelect(filterList, func(selected string) {
		appLogger.Debug("选择过滤器：%s", selected)
		updateFilterDescription(selected) // 使用现有的更新函数
	})
	filterSelect.SetSelected(filterList[0]) // 设置默认选择第一个过滤器
	appLogger.Debug("初始化过滤器选择框，默认选择：%s", filterList[0])
	updateFilterDescription(filterList[0]) // 初始化描述

	// 管理员验证用户按钮
	adminTestUserButton := widget.NewButton("admin账号验证用户", func() {
		appLogger.Debug("开始管理员验证用户操作")
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			appLogger.Error("验证失败：用户名或密码为空")
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
		appLogger.Debug("使用过滤器：%s", filterPattern)

		port, err := portEntry.GetPort()
		if err != nil {
			appLogger.Error("获取端口失败：%v", err)
			dialog.ShowError(err, myWindow)
			return
		}
		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       adminEntry.Text,
			BindPassword: passwordEntry.Text,
			UpdateFunc:   updateStatus,
			Logger:       appLogger,
			UseTLS:       isSSLEnabled,
			DebugMode:    debugMode,
		}
		appLogger.Debug("创建LDAP客户端，使用管理员账号：%s", adminEntry.Text)

		appLogger.Info("使用 %s 过滤器开始验证用户...", filterSelect.Selected)
		if client.TestUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, filterPattern) {
			appLogger.Info("测试用户验证成功")
		} else {
			appLogger.Warn("测试用户验证失败")
		}
	})

	// LDAP账号验证用户按钮
	ldapTestUserButton := widget.NewButton("LDAP账号验证用户", func() {
		appLogger.Debug("开始LDAP账号验证用户操作")
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			appLogger.Error("验证失败：用户名或密码为空")
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
		appLogger.Debug("使用过滤器：%s", filterPattern)

		port, err := portEntry.GetPort()
		if err != nil {
			appLogger.Error("获取端口失败：%v", err)
			dialog.ShowError(err, myWindow)
			return
		}
		client := ldap.LDAPClient{
			Host:         domainEntry.Text,
			Port:         port,
			BindDN:       ldapDNEntry.Text,
			BindPassword: ldapPasswordEntry.Text,
			UpdateFunc:   updateStatus,
			Logger:       appLogger,
			UseTLS:       isSSLEnabled,
			DebugMode:    debugMode,
		}
		appLogger.Debug("创建LDAP客户端，使用LDAP账号：%s", ldapDNEntry.Text)

		appLogger.Info("使用 %s 过滤器开始验证用户...", filterSelect.Selected)
		if client.TestUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, filterPattern) {
			appLogger.Info("测试用户验证成功")
		} else {
			appLogger.Warn("测试用户验证失败")
		}
	})

	// SSL支持复选框
	widget.NewCheck("SSL支持", func(checked bool) {
		appLogger.Debug("SSL支持状态改变：%v -> %v", isSSLEnabled, checked)
		isSSLEnabled = checked // 更新SSL状态
		if checked {
			appLogger.Debug("切换到SSL模式，设置默认SSL端口")
			portEntry.SetDefaultPort(true)                         // SSL端口
			ldapPasswordEntry.SetPlaceHolder("SSL模式下创建的用户是可以直接用的") // 更新占位符提示
		} else {
			appLogger.Debug("切换到非SSL模式，设置默认标准端口")
			portEntry.SetDefaultPort(false)                          // 标准端口
			ldapPasswordEntry.SetPlaceHolder("非SSL模式创建的用户是没有密码停用的）") // 更新占位符提示
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
				filterDescLabel,
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
	appLogger.Debug("构建窗口布局")
	content := container.NewBorder(
		// 顶部固定内容
		container.NewVBox(
			container.NewHBox(
				widget.NewLabel("LDAP 服务测试"),
				layout.NewSpacer(),
				widget.NewCheck("调试模式 (跳过TLS验证)", func(checked bool) {
					appLogger.Debug("调试模式状态改变：%v", checked)
					// 更新所有LDAP客户端实例的调试模式设置
					debugMode = checked

					// 记录调试模式状态变化的明确提示
					if checked {
						appLogger.Info("已开启调试模式，将跳过TLS证书验证")
					} else {
						appLogger.Info("已关闭调试模式，将执行TLS证书验证")
					}
				}),
			),
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
	appLogger.Debug("设置窗口默认大小：600x600")
	myWindow.Resize(fyne.NewSize(600, 600))

	// 设置窗口关闭事件
	myWindow.SetOnClosed(func() {
		appLogger.Info("应用程序正在关闭，清理资源...")
		appLogger.Info("资源清理完成，应用程序退出")
	})

	appLogger.Debug("启动主窗口")
	myWindow.ShowAndRun()
}
