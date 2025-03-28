package main

import (
	"flag"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"LdapTest/ldap"
	"LdapTest/logger"
	"LdapTest/ui"
)

// 全局变量，用于控制调试模式
var debugMode bool
var appLogger *logger.BaseLogger

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
	baseLogger := logger.New(debugMode, updateStatus)
	appLogger = baseLogger.NewBaseLogger(updateStatus)

	// 记录应用程序启动信息
	debugModeStr := "false"
	if debugMode {
		debugModeStr = "true"
	}
	appLogger.Info("应用程序启动，调试模式：" + debugModeStr)

	// 创建过滤器选择框
	appLogger.Debug("初始化过滤器选择框")
	filterList := func() []string {
		var names []string
		names = append(names, "(Select one)")
		for _, f := range ldap.CommonFilters() {
			names = append(names, f.Name)
		}
		appLogger.Debug("加载过滤器列表：%s", strings.Join(names, ", "))
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

	// 创建LDAP操作处理器
	ldapOps := ui.NewLDAPOperations(myWindow, appLogger, updateStatus, debugMode, ui.NewCustomFilterSelect(filterList, func(selected string) {
		updateFilterDescription(selected)
	}))

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
		ldapOps.HandlePing(domainEntry.Text)
	})

	portTestButton := widget.NewButton("测试服务", func() {
		ldapOps.HandlePortTest(domainEntry.Text, portEntry, isSSLEnabled)
	})

	adminTestButton := widget.NewButton("测试管理员", func() {
		ldapOps.HandleAdminTest(domainEntry.Text, adminEntry.Text, passwordEntry.Text, portEntry, isSSLEnabled)
	})

	// 创建LDAP用户按钮
	createLdapButton := widget.NewButton("创建LDAP用户", func() {
		ldapOps.HandleCreateLdap(domainEntry.Text, adminEntry.Text, passwordEntry.Text, ldapDNEntry.Text, ldapPasswordEntry.Text, ldapGroupEntry.Text, searchDNEntry.Text, portEntry, isSSLEnabled)
	})

	// 检查权限组按钮
	groupButton := widget.NewButton("检查权限组", func() {
		ldapOps.HandleGroupCheck(domainEntry.Text, adminEntry.Text, passwordEntry.Text, ldapGroupEntry.Text, searchDNEntry.Text, portEntry, isSSLEnabled)
	})

	// 管理员验证用户按钮
	adminTestUserButton := widget.NewButton("admin账号验证用户", func() {
		ldapOps.HandleAdminTestUser(domainEntry.Text, adminEntry.Text, passwordEntry.Text, testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, portEntry, isSSLEnabled)
	})

	// LDAP账号验证用户按钮
	ldapTestUserButton := widget.NewButton("LDAP账号验证用户", func() {
		ldapOps.HandleLdapTestUser(domainEntry.Text, ldapDNEntry.Text, ldapPasswordEntry.Text, testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text, portEntry, isSSLEnabled)
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

	// 过滤器选择框
	filterSelect := widget.NewSelect(filterList, func(selected string) {
		appLogger.Debug("选择过滤器：%s", selected)
		updateFilterDescription(selected) // 使用现有的更新函数
	})
	filterSelect.SetSelected(filterList[0]) // 设置默认选择第一个过滤器
	appLogger.Debug("初始化过滤器选择框，默认选择：%s", filterList[0])
	updateFilterDescription(filterList[0]) // 初始化描述

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
				widget.NewCheck("调试模式", func(checked bool) {
					appLogger.Debug("调试模式状态改变：%v", checked)
					debugMode = checked
					// 更新LDAP客户端的调试模式
					ldapOps.SetDebugMode(checked)
					if checked {
						appLogger.Info("已开启调试模式，将输出详细日志")
					} else {
						appLogger.Info("已关闭调试模式，将只输出重要日志")
					}
				}),
				widget.NewCheck("跳过TLS验证", func(checked bool) {
					appLogger.Debug("TLS验证状态改变：%v", checked)
					// 更新所有LDAP客户端实例的TLS验证设置
					ldap.SetSkipTLSVerify(checked)

					// 记录TLS验证状态变化的明确提示
					if checked {
						appLogger.Info("将跳过TLS证书验证")
					} else {
						appLogger.Info("将执行TLS证书验证")
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
