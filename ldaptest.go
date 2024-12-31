package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/go-ldap/ldap/v3"
)

type LDAPClient struct {
	host     string
	port     int
	userDN   string
	password string
}

func (client *LDAPClient) isPortOpen() bool {
	address := fmt.Sprintf("%s:%d", client.host, client.port)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (client *LDAPClient) testLDAPService() bool {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
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
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.host, client.port))
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

func main() {
	// 只保留字体设置
	os.Setenv("FYNE_FONT", "C:\\Windows\\Fonts\\SIMYOU.TTF")

	myApp := app.New()
	myWindow := myApp.NewWindow("LDAP Client")

	// 创建简单的输入框和标签
	hostEntry := widget.NewEntry()
	hostEntry.SetText("ldap.example.com")
	hostEntry.SetPlaceHolder("请输入LDAP服务器地址")

	// 使用简单的状态标签
	statusLabel := widget.NewLabel("")

	// 简化 ping 测试按钮
	pingButton := widget.NewButton("连接测试", func() {
		host := hostEntry.Text
		if host == "" {
			statusLabel.SetText("请输入服务器地址")
			return
		}

		statusLabel.SetText("开始ping测试...")

		go func() {
			cmd := exec.Command("ping", "-n", "4", host)
			output, err := cmd.CombinedOutput()
			if err != nil {
				statusLabel.SetText(fmt.Sprintf("ping测试失败: %v", err))
				return
			}

			outputStr := string(output)
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
				statusLabel.SetText(fmt.Sprintf("ping测试结束，服务器可以连接，平均延迟为%s", avgTime))
			} else {
				statusLabel.SetText("ping测试结束，服务器可以连接，但无法获取平均延迟")
			}
		}()
	})

	// 使用简单的垂直布局
	content := container.NewVBox(
		hostEntry,
		pingButton,
		statusLabel,
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
