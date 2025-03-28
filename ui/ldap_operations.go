package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"LdapTest/ldap"
	"LdapTest/logger"
	"fmt"
	"os/exec"
	"strings"
)

// CustomFilterSelect 自定义过滤器选择框
type CustomFilterSelect struct {
	*widget.Select
}

// NewCustomFilterSelect 创建新的自定义过滤器选择框
func NewCustomFilterSelect(options []string, onSelected func(string)) *CustomFilterSelect {
	return &CustomFilterSelect{
		Select: widget.NewSelect(options, onSelected),
	}
}

// Selected 获取当前选中的过滤器名称
func (c *CustomFilterSelect) Selected() string {
	return c.Select.Selected
}

// LDAPOperations 处理所有LDAP相关的界面交互
type LDAPOperations struct {
	window       fyne.Window
	logger       *logger.BaseLogger
	client       *ldap.LDAPClient
	isSSLMode    bool
	updateStatus func(string)
	debugMode    bool
	filterSelect *CustomFilterSelect
}

// NewLDAPOperations 创建新的LDAP操作处理器
func NewLDAPOperations(window fyne.Window, logger *logger.BaseLogger, updateStatus func(string), debugMode bool, filterSelect *CustomFilterSelect) *LDAPOperations {
	return &LDAPOperations{
		window:       window,
		logger:       logger,
		updateStatus: updateStatus,
		debugMode:    debugMode,
		filterSelect: filterSelect,
	}
}

// HandleExistingUser 处理已存在用户的情况
func (ops *LDAPOperations) HandleExistingUser(userDN string, password string, groupDN string, searchDN string) {
	sslMode := "false"
	if ops.isSSLMode {
		sslMode = "true"
	}
	ops.logger.Info("处理已存在用户，DN: " + userDN + ", SSL模式: " + sslMode)
	if ops.isSSLMode {
		dialog.ShowConfirm("用户已存在",
			"用户已存在且位置相同：\n"+userDN+"\n\n是否要更新用户密码？",
			func(updatePassword bool) {
				if updatePassword {
					ops.logger.Info("开始更新用户密码...")
					if err := ops.client.UpdateUserPassword(userDN, password); err != nil {
						ops.logger.Error("密码更新失败：" + err.Error())
						dialog.ShowError(err, ops.window)
						return
					}
					ops.logger.Info("用户密码更新成功")
				} else {
					ops.logger.Info("保持用户密码不变：" + userDN)
				}
				ops.PromptForGroupMembership(userDN, groupDN, searchDN)
			}, ops.window)
	} else {
		dialog.ShowConfirm("用户已存在",
			"用户已存在且位置相同：\n"+userDN+"\n\n非SSL模式下无法更新密码，是否继续？",
			func(confirmed bool) {
				if confirmed {
					ops.logger.Debug("用户确认继续操作")
					ops.logger.Info("用户已存在：" + userDN)
					ops.PromptForGroupMembership(userDN, groupDN, searchDN)
				} else {
					ops.logger.Debug("用户取消操作")
					ops.logger.Info("操作已取消")
				}
			}, ops.window)
	}
}

// HandleUserMove 处理用户移动的情况
func (ops *LDAPOperations) HandleUserMove(currentDN string, targetDN string, password string, groupDN string, searchDN string) {
	sslMode := "false"
	if ops.isSSLMode {
		sslMode = "true"
	}
	ops.logger.Debug("处理用户移动，当前DN: " + currentDN + ", 目标DN: " + targetDN + ", SSL模式: " + sslMode)
	dialog.ShowConfirm("用户已存在",
		"发现同名用户：\n"+currentDN+"\n\n当前输入位置：\n"+targetDN+"\n\n是否要移动用户？",
		func(move bool) {
			if move {
				ops.logger.Debug("用户确认移动操作")
				ops.logger.Info("正在移动用户 " + currentDN + " -> " + targetDN)
				if err := ops.client.MoveUserToNewLocation(currentDN, targetDN); err != nil {
					ops.logger.Error("用户移动失败：" + err.Error())
					dialog.ShowError(err, ops.window)
					return
				}
				ops.logger.Info("用户移动成功")
				ops.PromptForGroupMembership(targetDN, groupDN, searchDN)

				if ops.isSSLMode {
					ops.logger.Debug("SSL模式下，准备更新密码")
					ops.PromptForPasswordUpdate(targetDN, password)
				}
			} else {
				ops.logger.Debug("用户取消移动操作，使用现有位置")
				ops.logger.Info("已使用现有用户位置：" + currentDN)
				ops.PromptForGroupMembership(currentDN, groupDN, searchDN)
			}
		}, ops.window)
}

// PromptForGroupMembership 提示是否加入LDAP组
func (ops *LDAPOperations) PromptForGroupMembership(userDN string, groupDN string, searchDN string) {
	ops.logger.Debug("提示加入LDAP组，用户DN: " + userDN + ", 组DN: " + groupDN)
	dialog.ShowConfirm("添加到组",
		"是否要将用户加入LDAP组？\n用户: "+userDN+"\n组: "+groupDN,
		func(addToGroup bool) {
			if addToGroup {
				ops.logger.Debug("用户确认加入组操作")
				ops.logger.Info("正在将用户添加到组 " + groupDN)

				// 创建新的LDAP客户端
				client := ldap.NewLDAPClient(
					ops.client.Host,
					ops.client.Port,
					ops.client.BindDN,
					ops.client.BindPassword,
					ops.logger,
					ops.updateStatus,
					ops.isSSLMode,
					ops.debugMode,
				)

				// 确保连接有效
				if err := client.EnsureConnection(); err != nil {
					ops.logger.Error("连接失败：%v", err)
					dialog.ShowError(fmt.Errorf("连接失败: %v", err), ops.window)
					return
				}

				// 先移除所有现有组
				ops.logger.Info("正在移除用户的所有现有组...")
				if err := client.RemoveUserFromAllGroups(userDN, searchDN); err != nil {
					ops.logger.Error("移除现有组失败：" + err.Error())
					dialog.ShowError(fmt.Errorf("移除现有组失败: %v", err), ops.window)
					return
				}
				ops.logger.Info("已移除所有现有组")

				// 添加用户到新组
				if err := client.AddUserToGroup(userDN, groupDN); err != nil {
					ops.logger.Error("添加用户到组失败：" + err.Error())
					dialog.ShowError(err, ops.window)
					return
				}
				ops.logger.Info("用户成功添加到组")
			} else {
				ops.logger.Debug("用户取消加入组操作")
			}
		}, ops.window)
}

// PromptForPasswordUpdate 提示是否更新密码
func (ops *LDAPOperations) PromptForPasswordUpdate(userDN string, password string) {
	ops.logger.Debug("提示更新密码，用户DN: " + userDN)
	dialog.ShowConfirm("更新密码",
		"是否要更新用户密码？",
		func(updatePassword bool) {
			if updatePassword {
				ops.logger.Debug("用户确认更新密码")
				ops.logger.Info("开始更新用户密码...")
				if err := ops.client.UpdateUserPassword(userDN, password); err != nil {
					ops.logger.Error("密码更新失败：" + err.Error())
					dialog.ShowError(err, ops.window)
					return
				}
				ops.logger.Info("用户密码更新成功")
			} else {
				ops.logger.Debug("用户取消密码更新")
			}
		}, ops.window)
}

// SetSSLMode 设置SSL模式
func (ops *LDAPOperations) SetSSLMode(isSSL bool) {
	ops.isSSLMode = isSSL
}

// SetClient 设置LDAP客户端
func (ops *LDAPOperations) SetClient(client *ldap.LDAPClient) {
	ops.client = client
}

// SetDebugMode 设置调试模式
func (ops *LDAPOperations) SetDebugMode(debug bool) {
	ops.debugMode = debug
	if ops.logger != nil {
		ops.logger.SetDebugMode(debug)
	}
	if ops.client != nil {
		ops.client.SetDebugMode(debug)
	}
}

// HandlePing 处理ping测试
func (ops *LDAPOperations) HandlePing(host string) {
	ops.logger.Info("开始Ping测试")

	if host == "" {
		ops.logger.Warn("服务器地址为空")
		ops.logger.Error("请输入服务器地址")
		return
	}
	ops.logger.Debug("Ping目标主机：%s", host)

	// 创建ping命令
	cmd := exec.Command("cmd", "/c", "chcp 65001 >nul && ping -n 4 "+host)
	ops.logger.Debug("执行命令：%s", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		ops.logger.Error("ping命令执行失败：%s", err.Error())
		return
	}

	// 解析ping输出
	outputStr := string(output)
	ops.logger.Debug("Ping输出：\n%s", outputStr)

	// 在Windows中，平均延迟信息位于包含"平均"的行中
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "平均") || strings.Contains(line, "Average") {
			ops.logger.Debug("找到平均延迟信息：%s", strings.TrimSpace(line))
			ops.logger.Info("ping测试完成，结果: %s", strings.TrimSpace(line))
			return
		}
	}

	// 如果没有找到平均时间行，至少显示最后一行结果
	if len(lines) > 0 {
		lastLine := lines[len(lines)-1]
		if lastLine == "" && len(lines) > 1 {
			lastLine = lines[len(lines)-2]
		}
		ops.logger.Debug("未找到平均延迟信息，使用最后一行：%s", strings.TrimSpace(lastLine))
		ops.logger.Info("ping测试完成: %s", strings.TrimSpace(lastLine))
	} else {
		ops.logger.Debug("ping输出为空")
		ops.logger.Warn("ping测试完成，但无法解析结果")
	}
}

// createLDAPClient 创建LDAP客户端
func (ops *LDAPOperations) createLDAPClient(domain string, bindDN string, bindPassword string, portEntry *CustomPortEntry, isSSL bool) (*ldap.LDAPClient, error) {
	port, err := portEntry.GetPort()
	if err != nil {
		ops.logger.Error("获取端口失败：%v", err)
		return nil, err
	}

	client := ldap.NewLDAPClient(
		domain,
		port,
		bindDN,
		bindPassword,
		ops.logger,
		ops.updateStatus,
		isSSL,
		ops.debugMode,
	)
	ops.logger.Debug("创建LDAP客户端，目标主机：%s", domain)
	return client, nil
}

// HandlePortTest 处理端口测试
func (ops *LDAPOperations) HandlePortTest(domain string, portEntry *CustomPortEntry, isSSL bool) {
	ops.logger.Debug("开始端口和服务测试")
	client, err := ops.createLDAPClient(domain, "", "", portEntry, isSSL)
	if err != nil {
		dialog.ShowError(err, ops.window)
		return
	}

	protocol := "LDAP"
	if isSSL {
		protocol = "LDAPS"
	}

	ops.logger.Info("开始测试 %s 服务，端口：%d", protocol, client.Port)

	// 第一步：测试端口
	ops.logger.Debug("第1步：测试 %s 端口 %d 是否开放", protocol, client.Port)
	if client.IsPortOpen() {
		ops.logger.Info("%s 端口 %d 已开放", protocol, client.Port)

		// 第二步：测试服务
		ops.logger.Debug("第2步：测试 %s 服务连接状态", protocol)

		conn, err := client.TestServiceConnection()
		if err != nil {
			ops.logger.Info("服务测试结果: %s 端口已开放，但服务连接异常", protocol)
		} else {
			conn.Close() // 确保连接关闭
			ops.logger.Info("服务测试结果: %s 端口已开放，服务正常运行", protocol)
		}
	} else {
		ops.logger.Warn("%s 端口 %d 未开放", protocol, client.Port)
		ops.logger.Info("服务测试结果: %s 端口未开放，无法测试服务", protocol)
	}
}

// HandleAdminTest 处理管理员测试
func (ops *LDAPOperations) HandleAdminTest(domain string, adminDN string, adminPassword string, portEntry *CustomPortEntry, isSSL bool) {
	ops.logger.Debug("开始测试管理员凭证")

	// 验证管理员密码不为空
	if adminDN == "" || adminPassword == "" {
		ops.logger.Error("验证失败：管理员DN或密码为空")
		dialog.ShowError(fmt.Errorf("管理员DN和密码不能为空"), ops.window)
		return
	}

	// 验证服务器地址不为空
	if domain == "" {
		ops.logger.Error("验证失败：服务器地址为空")
		dialog.ShowError(fmt.Errorf("请输入服务器地址"), ops.window)
		return
	}

	client, err := ops.createLDAPClient(domain, adminDN, adminPassword, portEntry, isSSL)
	if err != nil {
		dialog.ShowError(err, ops.window)
		return
	}

	protocol := "LDAP"
	if isSSL {
		protocol = "LDAPS"
	}

	ops.logger.Debug("测试 %s 服务，端口：%d", protocol, client.Port)

	// 分步骤测试
	if client.IsPortOpen() {
		ops.logger.Debug("%s 端口 %d 已开放", protocol, client.Port)

		if client.TestLDAPService() {
			ops.logger.Info("%s 服务正常运行，管理员认证成功", protocol)
		} else {
			ops.logger.Warn("%s 服务连接异常或管理员认证失败", protocol)
		}
	} else {
		ops.logger.Warn("%s 端口 %d 未开放", protocol, client.Port)
	}
}

// HandleGroupCheck 处理权限组检查
func (ops *LDAPOperations) HandleGroupCheck(domain string, adminDN string, adminPassword string, groupDN string, searchDN string, portEntry *CustomPortEntry, isSSL bool) {
	ops.logger.Debug("开始检查权限组操作")
	port, err := portEntry.GetPort()
	if err != nil {
		ops.logger.Error("获取端口失败：%v", err)
		dialog.ShowError(err, ops.window)
		return
	}
	ops.logger.Debug("使用端口：%d，SSL模式：%v", port, isSSL)

	client := ldap.NewLDAPClient(
		domain,
		port,
		adminDN,
		adminPassword,
		ops.logger,
		ops.updateStatus,
		isSSL,
		ops.debugMode,
	)
	ops.logger.Debug("创建LDAP客户端，目标主机：%s", domain)

	// 先检查端口连通性
	if !client.IsPortOpen() {
		ops.logger.Warn("端口 %d 未开放", port)
		return
	}
	ops.logger.Debug("端口连通性检查通过")

	// 验证管理员凭证
	if !client.TestLDAPService() {
		ops.logger.Error("管理员认证失败，BindDN: %s", adminDN)
		dialog.ShowError(fmt.Errorf("管理员认证失败\n可能原因：\n1. 密码错误\n2. DN格式错误\n3. 权限不足\n4. 证书验证失败"), ops.window)
		return
	}
	ops.logger.Info("管理员认证成功")

	// 从输入的组DN中提取CN
	enteredGroupCN := strings.SplitN(groupDN, ",", 2)[0]
	if !strings.HasPrefix(enteredGroupCN, "CN=") {
		ops.logger.Error("组DN格式无效：%s", groupDN)
		return
	}
	groupName := strings.TrimPrefix(enteredGroupCN, "CN=")
	ops.logger.Debug("提取组名：%s", groupName)

	// 检查组是否已存在
	found, foundGroupDN := client.SearchGroup(groupName, searchDN)
	if found {
		ops.logger.Debug("发现已存在组，DN: %s", foundGroupDN)
		// 当DN完全相同时（不区分大小写）
		if strings.EqualFold(strings.ToLower(foundGroupDN), strings.ToLower(groupDN)) {
			// 提示是否需要重新授权
			dialog.ShowConfirm("组已存在",
				fmt.Sprintf("组已存在且位置正确：\n%s\n\n是否要重新授权该组？", foundGroupDN),
				func(reauth bool) {
					if reauth {
						ops.logger.Debug("用户确认重新授权组：%s", foundGroupDN)
						ops.logger.Info("开始重新授权组权限...")

						// 获取有效连接
						_, err := client.GetConnection()
						if err != nil {
							ops.logger.Error("获取连接失败：%v", err)
							dialog.ShowError(fmt.Errorf("连接失败: %v", err), ops.window)
							return
						}
						ops.logger.Debug("成功获取LDAP连接")

						// 创建修改请求
						attributes := map[string][]string{
							"groupType":   {"-2147483646"},
							"description": {"LDAP Authentication Group"},
						}
						ops.logger.Debug("准备修改组属性：%v", attributes)
						if err := client.ModifyGroup(groupDN, attributes); err != nil {
							ops.logger.Error("修改组属性失败：%v", err)
							dialog.ShowError(fmt.Errorf("重新授权失败: %s", ldap.ParseLDAPError(err)), ops.window)
							return
						}

						// 配置SSO所需的ACL权限
						ops.logger.Debug("开始配置组的SSO权限")
						if err := client.ConfigureGroupForSSO(groupDN, searchDN); err != nil {
							ops.logger.Error("配置SSO权限失败：%v", err)
							dialog.ShowError(fmt.Errorf("SSO权限配置失败: %s", ldap.ParseLDAPError(err)), ops.window)
							return
						}
						ops.logger.Info("组属性修改成功")
						ops.logger.Info("SSO权限配置成功：%s", groupDN)
					} else {
						ops.logger.Debug("用户取消重新授权组")
						ops.logger.Info("保持现有组权限不变：%s", foundGroupDN)
					}
				}, ops.window)
			return
		}

		// 原有的移动组逻辑保持不变
		dialog.ShowConfirm("组已存在",
			fmt.Sprintf("发现同名组：\n%s\n\n当前输入位置：\n%s\n\n是否要移动组？",
				foundGroupDN,
				groupDN),
			func(move bool) {
				if move {
					ops.logger.Debug("用户确认移动组，从 %s 到 %s", foundGroupDN, groupDN)
					ops.logger.Info("正在移动组 %s -> %s", foundGroupDN, groupDN)
					if err := client.MoveUser(foundGroupDN, groupDN); err != nil {
						ops.logger.Error("移动组失败：%v", err)
						dialog.ShowError(fmt.Errorf("移动失败: %s", ldap.ParseLDAPError(err)), ops.window)
						return
					}
					ops.logger.Info("组移动成功")
				} else {
					ops.logger.Debug("用户取消移动组，使用现有位置：%s", foundGroupDN)
					ops.logger.Info("已使用现有组位置：%s", foundGroupDN)
				}
			}, ops.window)
		return
	}

	// 不存在则继续创建流程
	ops.logger.Info("未找到同名组，准备创建新组：%s", groupDN)

	// 创建新组
	if err := client.CreateGroup(groupDN, groupName); err != nil {
		ops.logger.Error("创建组失败：%v", err)
		dialog.ShowError(fmt.Errorf("创建组失败: %s", ldap.ParseLDAPError(err)), ops.window)
		return
	}

	ops.logger.Info("成功创建新组：%s", groupDN)
}

// HandleCreateLdap 处理创建LDAP用户
func (ops *LDAPOperations) HandleCreateLdap(domain string, adminDN string, adminPassword string, ldapDN string, ldapPassword string, groupDN string, searchDN string, portEntry *CustomPortEntry, isSSL bool) {
	ops.logger.Debug("开始创建LDAP用户操作")
	ops.isSSLMode = isSSL // 设置SSL模式

	// 输入验证
	if ldapDN == "" {
		ops.logger.Error("验证失败：LDAP DN不能为空")
		dialog.ShowError(fmt.Errorf("LDAP DN不能为空"), ops.window)
		return
	}
	if isSSL && ldapPassword == "" {
		ops.logger.Error("验证失败：SSL模式下密码不能为空")
		dialog.ShowError(fmt.Errorf("SSL模式下LDAP密码不能为空"), ops.window)
		return
	}

	// 验证管理员凭据
	if adminDN == "" || adminPassword == "" {
		ops.logger.Error("验证失败：管理员DN或密码为空")
		dialog.ShowError(fmt.Errorf("管理员DN和密码不能为空"), ops.window)
		return
	}

	port, err := portEntry.GetPort()
	if err != nil {
		ops.logger.Error("获取端口失败：%v", err)
		dialog.ShowError(err, ops.window)
		return
	}
	ops.logger.Debug("使用端口：%d，SSL模式：%v", port, isSSL)

	// 使用管理员凭据创建客户端
	client := ldap.NewLDAPClient(
		domain,
		port,
		adminDN,       // 使用管理员DN
		adminPassword, // 使用管理员密码
		ops.logger,
		ops.updateStatus,
		isSSL,
		ops.debugMode,
	)
	ops.logger.Debug("创建LDAP客户端，目标主机：%s", domain)
	ops.SetClient(client) // 设置客户端实例

	// 先检查端口连通性
	if !client.IsPortOpen() {
		ops.logger.Warn("端口 %d 未开放", port)
		return
	}
	ops.logger.Debug("端口连通性检查通过")

	// 验证管理员凭证
	if !client.TestLDAPService() {
		ops.logger.Error("管理员认证失败，BindDN: %s", adminDN)
		dialog.ShowError(fmt.Errorf("管理员认证失败\n可能原因：\n1. 密码错误\n2. DN格式错误\n3. 权限不足"), ops.window)
		return
	}
	ops.logger.Info("管理员认证成功")

	// 从输入的DN中提取CN
	enteredCN := strings.SplitN(ldapDN, ",", 2)[0]
	if !strings.HasPrefix(enteredCN, "CN=") {
		ops.logger.Error("DN格式无效：%s", ldapDN)
		return
	}
	userName := strings.TrimPrefix(enteredCN, "CN=")
	ops.logger.Debug("提取用户名：%s", userName)

	// 检查用户是否存在
	found, foundUserDN := client.SearchUser(userName, searchDN)
	if found {
		ops.logger.Debug("发现已存在用户，DN: %s", foundUserDN)
		// 当DN完全相同时（不区分大小写）
		if strings.EqualFold(strings.ToLower(foundUserDN), strings.ToLower(ldapDN)) {
			ops.logger.Debug("用户位置相同，处理已存在用户情况")
			ops.HandleExistingUser(foundUserDN, ldapPassword, groupDN, searchDN)
			return
		}

		// 用户存在但位置不同，询问是否移动
		ops.logger.Debug("用户存在但位置不同，当前位置：%s，目标位置：%s", foundUserDN, ldapDN)
		ops.HandleUserMove(foundUserDN, ldapDN, ldapPassword, groupDN, searchDN)
		return
	}

	// 不存在则创建新用户
	ops.logger.Info("未找到已存在用户，开始创建新用户")
	err = client.CreateOrUpdateUser(ldapDN, userName, ldapPassword, isSSL)
	if err != nil {
		ops.logger.Error("创建用户失败：%v", err)
		// 检查是否是用户已存在的错误
		if strings.Contains(err.Error(), "Entry Already Exists") {
			dialog.ShowError(fmt.Errorf("创建用户失败：用户已存在\n请检查搜索范围是否正确"), ops.window)
		} else {
			dialog.ShowError(fmt.Errorf("创建用户失败：%s", err), ops.window)
		}
		return
	}
	ops.logger.Info("用户创建成功")

	// 询问是否要将用户加入LDAP组
	ops.logger.Debug("准备处理组成员关系，组DN: %s", groupDN)
	ops.PromptForGroupMembership(ldapDN, groupDN, searchDN)
}

// HandleTestUser 处理用户验证（支持管理员和LDAP账号）
func (ops *LDAPOperations) HandleTestUser(domain string, bindDN string, bindPassword string, testUser string, testPassword string, searchDN string, portEntry *CustomPortEntry, isSSL bool) {
	ops.logger.Debug("开始用户验证操作")
	if testUser == "" || testPassword == "" {
		ops.logger.Error("验证失败：用户名或密码为空")
		return
	}

	client, err := ops.createLDAPClient(domain, bindDN, bindPassword, portEntry, isSSL)
	if err != nil {
		dialog.ShowError(err, ops.window)
		return
	}

	// 获取选定的过滤器模式
	var filterPattern string
	for _, f := range ldap.CommonFilters() {
		if f.Name == ops.filterSelect.Selected() {
			filterPattern = f.Pattern
			break
		}
	}
	ops.logger.Debug("使用过滤器：%s", filterPattern)

	ops.logger.Info("使用 %s 过滤器开始验证用户...", ops.filterSelect.Selected())
	if client.TestUserAuth(testUser, testPassword, searchDN, filterPattern) {
		ops.logger.Info("测试用户验证成功")
	} else {
		ops.logger.Warn("测试用户验证失败")
	}
}

// HandleAdminTestUser 处理管理员验证用户
func (ops *LDAPOperations) HandleAdminTestUser(domain string, adminDN string, adminPassword string, testUser string, testPassword string, searchDN string, portEntry *CustomPortEntry, isSSL bool) {
	ops.HandleTestUser(domain, adminDN, adminPassword, testUser, testPassword, searchDN, portEntry, isSSL)
}

// HandleLdapTestUser 处理LDAP账号验证用户
func (ops *LDAPOperations) HandleLdapTestUser(domain string, ldapDN string, ldapPassword string, testUser string, testPassword string, searchDN string, portEntry *CustomPortEntry, isSSL bool) {
	ops.HandleTestUser(domain, ldapDN, ldapPassword, testUser, testPassword, searchDN, portEntry, isSSL)
}
