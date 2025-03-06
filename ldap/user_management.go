package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"unicode/utf16"

	"fyne.io/fyne/v2"
	"github.com/go-ldap/ldap/v3"
)

// EncodePassword 将密码编码为LDAP所需的格式
func EncodePassword(password string) string {
	// 将密码转换为UTF-16LE编码
	utf16Chars := utf16.Encode([]rune(password))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, char := range utf16Chars {
		bytes[i*2] = byte(char)
		bytes[i*2+1] = byte(char >> 8)
	}

	// 添加双引号
	quotedBytes := append([]byte{'"'}, bytes...)
	quotedBytes = append(quotedBytes, '"')

	return string(quotedBytes)
}

// SearchUserInDomain 在域中搜索用户
func (client *LDAPClient) SearchUserInDomain(username string) (bool, string) {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		log.Printf("搜索用户时连接失败: %v", err)
		return false, ""
	}

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		client.BindDN, // 使用绑定DN作为搜索基准
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("搜索用户失败: %v", err)
		return false, ""
	}

	// 检查是否找到用户
	if len(sr.Entries) > 0 {
		return true, sr.Entries[0].DN
	}

	return false, ""
}

// TestUserAuth 测试用户认证
func (client *LDAPClient) TestUserAuth(testUser, testPassword, searchDN, filterPattern string) bool {
	// 确保连接有效
	if err := client.EnsureConnection(); err != nil {
		log.Printf("测试用户认证时连接失败: %v", err)
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("连接失败: %v", err))
		}
		return false
	}

	// 构建搜索过滤器
	filter := fmt.Sprintf(filterPattern, ldap.EscapeFilter(testUser))

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"distinguishedName"},
		nil,
	)

	// 执行搜索
	sr, err := client.Conn.Search(searchRequest)
	if err != nil {
		log.Printf("搜索用户失败: %v", err)
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("搜索用户失败: %v", err))
		}
		return false
	}

	// 检查是否找到用户
	if len(sr.Entries) == 0 {
		log.Printf("未找到用户: %s", testUser)
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("未找到用户: %s", testUser))
		}
		return false
	}

	// 获取用户DN
	userDN := sr.Entries[0].DN

	// 创建新的连接进行用户认证
	var authConn *ldap.Conn
	var connErr error

	if client.UseTLS {
		// 使用TLS连接
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		authConn, connErr = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", client.Host, client.Port), tlsConfig)
	} else {
		// 使用普通连接
		authConn, connErr = ldap.Dial("tcp", fmt.Sprintf("%s:%d", client.Host, client.Port))
	}

	if connErr != nil {
		log.Printf("创建认证连接失败: %v", connErr)
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("创建认证连接失败: %v", connErr))
		}
		return false
	}
	defer authConn.Close()

	// 尝试使用用户凭证绑定
	if err := authConn.Bind(userDN, testPassword); err != nil {
		log.Printf("用户认证失败: %v", err)
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("用户认证失败: %v", err))
		}
		return false
	}

	// 认证成功
	log.Printf("用户认证成功: %s", userDN)
	return true
}

// CreateUserWithoutSSL 在非SSL模式下创建用户（禁用状态）
func CreateUserWithoutSSL(conn *ldap.Conn, userDN string, userName string, host string, updateFunc func(string)) error {
	// 创建用户请求
	addRequest := ldap.NewAddRequest(userDN, nil)

	// 设置必要的属性
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("sAMAccountName", []string{userName})
	addRequest.Attribute("userAccountControl", []string{"514"}) // 禁用账户

	// 执行创建
	if err := conn.Add(addRequest); err != nil {
		return fmt.Errorf("创建用户失败: %v", err)
	}

	if updateFunc != nil {
		updateFunc(fmt.Sprintf("成功创建用户: %s (禁用状态)", userDN))
	}

	return nil
}

// CreateUserWithSSL 在SSL模式下创建用户（启用状态并设置密码）
func CreateUserWithSSL(conn *ldap.Conn, client *LDAPClient, userDN string, userName string, password string, host string, myWindow fyne.Window, updateFunc func(string)) error {
	// 创建用户请求
	addRequest := ldap.NewAddRequest(userDN, nil)

	// 设置必要的属性
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("sAMAccountName", []string{userName})
	addRequest.Attribute("userAccountControl", []string{"512"}) // 启用账户

	// 设置密码
	encodedPassword := EncodePassword(password)
	addRequest.Attribute("unicodePwd", []string{encodedPassword})

	// 执行创建
	if err := conn.Add(addRequest); err != nil {
		return fmt.Errorf("创建用户失败: %v", err)
	}

	if updateFunc != nil {
		updateFunc(fmt.Sprintf("成功创建用户: %s (启用状态)", userDN))
	}

	return nil
}
