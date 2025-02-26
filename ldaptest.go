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

type LDAPClient struct {
	host     string
	port     int
	userDN   string
	password string
}

func (client *LDAPClient) isPortOpen() bool {
	address := net.JoinHostPort(client.host, fmt.Sprintf("%d", client.port))
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (client *LDAPClient) testLDAPService() bool {
	url := fmt.Sprintf("ldap://%s:%d", client.host, client.port)
	l, err := ldap.DialURL(url)
	if err != nil {
		log.Println("Failed to connect:", err)
		return false
	}
	defer l.Close()

	err = l.Bind(client.userDN, client.password)
	if err != nil {
		log.Println("Failed to bind:", err)
		return false
	}

	log.Println("LDAP service verified successfully")
	return true
}

func (client *LDAPClient) testUserAuth(testUser, testPassword, searchDN string) bool {
	url := fmt.Sprintf("ldap://%s:%d", client.host, client.port)
	l, err := ldap.DialURL(url)
	if err != nil {
		log.Println("Failed to connect:", err)
		return false
	}
	defer l.Close()

	// 先用管理员账号绑定
	err = l.Bind(client.userDN, client.password)
	if err != nil {
		log.Println("Admin bind failed:", err)
		return false
	}

	// 使用传入的搜索 DN
	searchRequest := ldap.NewSearchRequest(
		searchDN, // 使用输入框中的搜索 DN
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", testUser),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Println("Search failed:", err)
		return false
	}

	if len(sr.Entries) != 1 {
		log.Println("User not found or too many entries returned")
		return false
	}

	// 使用找到的用户 DN 进行绑定测试
	userDN := sr.Entries[0].DN
	err = l.Bind(userDN, testPassword)
	if err != nil {
		log.Println("Test user bind failed:", err)
		return false
	}

	log.Println("Test user authenticated successfully")
	return true
}

type myTheme struct {
	fyne.Theme
}

func (m myTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameDisabled {
		return &color.NRGBA{R: 0, G: 0, B: 0, A: 255} // 纯黑色
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (m myTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (m myTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (m myTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

func main() {
	os.Setenv("FYNE_FONT", "C:\\Windows\\Fonts\\SIMYOU.TTF")
	myApp := app.New()
	myApp.Settings().SetTheme(&myTheme{})
	myWindow := myApp.NewWindow("LDAP Client")

	// 创建输入框和标签
	hostEntry := widget.NewEntry()
	hostEntry.SetText("ldap.example.com")
	hostEntry.SetPlaceHolder("请输入LDAP服务器地址")

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("请输入LDAP服务器端口")

	userDNEntry := widget.NewEntry()
	userDNEntry.SetPlaceHolder("请输入管理员DN")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("请输入管理员密码")

	// 在 passwordEntry 后添加搜索 DN 输入框
	searchDNEntry := widget.NewEntry()
	searchDNEntry.SetPlaceHolder("请输入搜索DN")
	searchDNEntry.SetText("dc=example,dc=com") // 设置默认值

	// 添加测试用户的输入框
	testUserEntry := widget.NewEntry()
	testUserEntry.SetPlaceHolder("请输入测试用户名")

	testPasswordEntry := widget.NewPasswordEntry()
	testPasswordEntry.SetPlaceHolder("请输入测试密码")

	// 将 statusLabel 改为带滚动条的多行文本输入框
	statusArea := widget.NewMultiLineEntry()
	statusArea.Disable()                    // 设置为只读
	statusArea.Wrapping = fyne.TextWrapWord // 启用自动换行

	// 创建一个背景矩形来控制最小大小，高度设置为显示2行（约80像素）
	background := canvas.NewRectangle(color.Transparent)
	background.SetMinSize(fyne.NewSize(400, 60))

	// 使用容器来控制大小，确保状态区域至少有一定的高度
	statusContainer := container.NewStack(
		background,
		container.NewVScroll(statusArea),
	)

	// 创建一个更新状态的辅助函数
	updateStatus := func(status string) {
		currentTime := time.Now().Format("15:04:05")
		// 使用 TextStyle 设置文本样式
		statusArea.TextStyle = fyne.TextStyle{
			Bold: true, // 设置为粗体
		}

		newText := statusArea.Text + currentTime + " " + status + "\n"
		statusArea.SetText(newText)
		// 滚动到底部
		statusArea.CursorRow = len(strings.Split(statusArea.Text, "\n")) - 1
	}

	pingButton := widget.NewButton("连接测试", func() {
		host := hostEntry.Text
		if host == "" {
			updateStatus("请输入服务器地址")
			return
		}

		updateStatus("开始ping测试...")

		go func() {
			cmd := exec.Command("ping", "-n", "4", host)
			output, err := cmd.CombinedOutput()
			if err != nil {
				updateStatus(fmt.Sprintf("ping测试失败: %v", err))
				return
			}

			decoder := simplifiedchinese.GBK.NewDecoder()
			utf8Output, _ := decoder.Bytes(output)
			outputStr := string(utf8Output)

			// 解析输出获取平均延迟
			// outputStr := string(output)
			var avgTime string

			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "平均 = ") {
					parts := strings.Split(line, "平均 = ")
					if len(parts) > 1 {
						avgTime = strings.TrimSpace(parts[1])
						break
					}
				} else if strings.Contains(line, "Average = ") {
					parts := strings.Split(line, "Average = ")
					if len(parts) > 1 {
						avgTime = strings.TrimSpace(parts[1])
						break
					}
				}
			}

			if avgTime != "" {
				updateStatus(fmt.Sprintf("ping测试结束，服务器可以连接，平均延迟为%s", avgTime))
			} else {
				updateStatus("ping测试结束，服务器可以连接，但无法获取平均延迟")
			}
		}()
	})

	portTestButton := widget.NewButton("端口测试", func() {
		host := hostEntry.Text
		port := 389 // 默认端口
		fmt.Sscanf(portEntry.Text, "%d", &port)
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, time.Second*3)
		if err != nil {
			updateStatus("端口未开放")
		} else {
			conn.Close()
			updateStatus("端口已开放")
		}
	})

	adminTestButton := widget.NewButton("管理测试", func() {
		client := LDAPClient{
			host:     hostEntry.Text,
			port:     389,
			userDN:   userDNEntry.Text,
			password: passwordEntry.Text,
		}
		if client.testLDAPService() {
			updateStatus("LDAP管理员验证成功")
		} else {
			updateStatus("LDAP管理员验证失败")
		}
	})

	// 创建一个函数来生成统一宽度的标签
	makeLabel := func(text string) fyne.CanvasObject {
		label := widget.NewLabel(text)
		label.TextStyle = fyne.TextStyle{Bold: true}
		label.Alignment = fyne.TextAlignTrailing // 文字右对齐

		// 创建一个固定宽度的容器来包装标签
		return container.NewHBox(
			layout.NewSpacer(), // 左侧弹性空间
			container.NewGridWrap(fyne.NewSize(100, 0), label), // 固定宽度的标签容器
		)
	}

	// 使用 Border 布局来实现自动拉伸
	formContainer := container.NewVBox(
		container.NewBorder(nil, nil, makeLabel("服务器地址:"), pingButton,
			hostEntry,
		),
		container.NewBorder(nil, nil, makeLabel("服务器端口:"), portTestButton,
			portEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Admin DN:"), nil,
			userDNEntry,
		),
		container.NewBorder(nil, nil, makeLabel("Admin密码:"), adminTestButton,
			passwordEntry,
		),
		container.NewBorder(nil, nil, makeLabel("搜索DN:"), nil,
			searchDNEntry,
		),
		container.NewBorder(nil, nil, makeLabel("测试用户:"), nil,
			testUserEntry,
		),
		container.NewBorder(nil, nil, makeLabel("测试密码:"), nil,
			testPasswordEntry,
		),
	)

	checkButton := widget.NewButton("测试 LDAP 连接", func() {
		// 必填字段验证
		host := hostEntry.Text
		if host == "" {
			dialog.ShowError(fmt.Errorf("服务器地址不能为空"), myWindow)
			updateStatus("错误：请填写服务器地址")
			return
		}
		if host == "ldap.example.com" {
			dialog.ShowError(fmt.Errorf("请修改默认服务器地址"), myWindow)
			updateStatus("错误：请填写实际服务器地址")
			return
		}
		if portEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("服务器端口不能为空"), myWindow)
			updateStatus("错误：请填写服务器端口")
			return
		}
		if userDNEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("admin DN 不能为空"), myWindow)
			updateStatus("错误：请填写dmin DN")
			return
		}
		if passwordEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("Admin密码不能为空"), myWindow)
			updateStatus("错误：请填写Admin密码")
			return
		}

		ldapPort := 389
		if _, err := fmt.Sscanf(portEntry.Text, "%d", &ldapPort); err != nil || ldapPort < 1 || ldapPort > 65535 {
			dialog.ShowError(fmt.Errorf("无效端口号：%s（必须是1-65535）", portEntry.Text), myWindow)
			updateStatus(fmt.Sprintf("错误：无效端口号 %s", portEntry.Text))
			return
		}

		client := LDAPClient{
			host:     hostEntry.Text,
			port:     ldapPort,
			userDN:   userDNEntry.Text,
			password: passwordEntry.Text,
		}

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

	testUserButton := widget.NewButton("测试用户验证", func() {
		if testUserEntry.Text == "" || testPasswordEntry.Text == "" {
			updateStatus("请输入测试用户名和密码")
			return
		}

		client := LDAPClient{
			host:     hostEntry.Text,
			port:     389,
			userDN:   userDNEntry.Text,
			password: passwordEntry.Text,
		}

		// 使用搜索 DN 输入框的值
		if client.testUserAuth(testUserEntry.Text, testPasswordEntry.Text, searchDNEntry.Text) {
			updateStatus("测试用户验证成功")
		} else {
			updateStatus("测试用户验证失败")
		}
	})

	// 修改窗口布局
	content := container.NewBorder(
		// 顶部固定内容
		container.NewVBox(
			widget.NewLabel("LDAP 服务测试"),
			formContainer,
			container.NewHBox(checkButton, testUserButton),
		),
		nil, // 底部
		nil, // 左侧
		nil, // 右侧
		// 中间自动填充的内容
		statusContainer,
	)

	myWindow.SetContent(content)

	// 增加窗口的默认大小，使状态区域有足够的显示空间
	myWindow.Resize(fyne.NewSize(400, 450))
	myWindow.ShowAndRun()
}
