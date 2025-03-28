package ldap

import (
	"errors"
	"strings"

	"fyne.io/fyne/v2"
	"github.com/go-ldap/ldap/v3"
)

// SearchUserInDomain 在域中搜索用户
func (client *LDAPClient) SearchUserInDomain(username string) (bool, string) {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		client.Error("搜索用户时连接失败: %v", err)
		return false, ""
	}

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		client.BindDN, // 使用绑定DN作为搜索基准
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=user)(sAMAccountName="+ldap.EscapeFilter(username)+"))",
		[]string{"dn"},
		nil,
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		client.Error("搜索用户失败: %v", err)
		return false, ""
	}

	// 检查是否找到用户
	if len(sr.Entries) > 0 {
		return true, sr.Entries[0].DN
	}

	return false, ""
}

// SearchUser 根据用户名搜索用户
func (client *LDAPClient) SearchUser(userName string, searchBase string) (bool, string) {
	client.Debug("正在搜索用户：%s，搜索范围：%s", userName, searchBase)
	// 获取有效连接
	conn, err := client.GetConnection()
	if err != nil {
		client.Error("连接失败: %v", err)
		return false, ""
	}

	// 构建搜索请求，按CN进行模糊查询
	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=user)(cn="+ldap.EscapeFilter(userName)+"))",
		[]string{"dn"},
		nil,
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		client.Error("搜索用户失败: %v", err)
		return false, ""
	}

	// 检查是否找到用户
	if len(sr.Entries) > 0 {
		return true, sr.Entries[0].DN
	}

	return false, ""
}

// TestUserAuth 测试用户认证
func (client *LDAPClient) TestUserAuth(testUser string, testPassword string, searchDN string, filterPattern string) bool {
	client.Debug("正在测试用户认证：%s，搜索范围：%s", testUser, searchDN)
	// 获取有效连接
	conn, err := client.GetConnection()
	if err != nil {
		client.Error("测试用户认证时连接失败: %v", err)
		return false
	}

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		searchDN,                                       // 基准DN
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, // 搜索范围和别名处理
		0, 0, false, // 大小限制，时间限制，仅类型
		strings.Replace(filterPattern, "%s", ldap.EscapeFilter(testUser), 1), // 搜索过滤器
		[]string{"dn"}, // 返回属性
		nil,
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		client.Error("搜索用户失败: %v", err)
		return false
	}

	// 检查结果
	if len(sr.Entries) == 0 {
		client.Warn("未找到用户: %s", testUser)
		return false
	}

	// 获取用户DN
	userDN := sr.Entries[0].DN

	// 创建新的连接用于认证
	authConn, connErr := client.GetConnection()
	if connErr != nil {
		client.Error("创建认证连接失败: %v", connErr)
		return false
	}
	defer authConn.Close()

	// 尝试使用用户凭据绑定
	err = authConn.Bind(userDN, testPassword)
	if err != nil {
		client.Error("用户认证失败: %v", err)
		return false
	}

	client.Info("用户认证成功: %s", userDN)
	return true
}

// CreateUserWithoutSSL 在非SSL模式下创建用户（禁用状态）
func (client *LDAPClient) CreateUserWithoutSSL(userDN string, userName string, host string) error {
	client.Debug("开始创建用户：%s", userDN)
	// 获取有效连接
	conn, err := client.GetConnection()
	if err != nil {
		return errors.New("获取连接失败: " + err.Error())
	}

	// 确保父容器存在
	parentDN := strings.SplitN(userDN, ",", 2)[1]
	if err := client.EnsureDNExists(parentDN); err != nil {
		return errors.New("创建路径失败: " + ParseLDAPError(err))
	}

	// 创建用户请求
	addRequest := ldap.NewAddRequest(userDN, nil)

	// 设置必要的属性
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("sAMAccountName", []string{userName})
	addRequest.Attribute("userAccountControl", []string{"514"}) // 禁用账户

	// 执行创建
	if err := conn.Add(addRequest); err != nil {
		return errors.New("创建用户失败: " + err.Error())
	}

	client.Info("成功创建用户: %s (禁用状态)", userDN)
	return nil
}

// CreateUserWithSSL 在SSL模式下创建用户（启用状态并设置密码）
func (client *LDAPClient) CreateUserWithSSL(userDN string, userName string, password string, host string, myWindow fyne.Window) error {
	client.Debug("开始创建用户，用户DN: %s", userDN)

	// 获取有效连接
	conn, err := client.GetConnection()
	if err != nil {
		return errors.New("获取连接失败: " + err.Error())
	}

	// 确保父容器存在
	parentDN := strings.SplitN(userDN, ",", 2)[1]
	if err := client.EnsureDNExists(parentDN); err != nil {
		return errors.New("创建路径失败: " + ParseLDAPError(err))
	}

	// 创建用户请求
	addRequest := ldap.NewAddRequest(userDN, nil)
	client.Debug("创建AddRequest对象成功")

	// 设置必要的属性
	client.Debug("开始设置用户属性")
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("sAMAccountName", []string{userName})
	addRequest.Attribute("userAccountControl", []string{"512"}) // 启用账户

	// 设置其他推荐属性
	addRequest.Attribute("name", []string{userName})
	addRequest.Attribute("displayName", []string{userName})
	addRequest.Attribute("givenName", []string{userName})
	addRequest.Attribute("sn", []string{userName})

	// 设置UPN
	domain := host
	if !strings.Contains(domain, ".") {
		// 尝试从userDN提取域名
		domainComponents := []string{}
		for _, part := range strings.Split(userDN, ",") {
			if strings.HasPrefix(strings.ToUpper(part), "DC=") {
				dc := strings.TrimPrefix(strings.ToUpper(part), "DC=")
				domainComponents = append(domainComponents, dc)
			}
		}
		if len(domainComponents) > 0 {
			domain = strings.Join(domainComponents, ".")
		}
	}
	upn := userName + "@" + domain
	client.Debug("设置UPN: %s", upn)
	addRequest.Attribute("userPrincipalName", []string{upn})

	// 设置密码
	client.Debug("开始设置用户密码")
	encodedPassword := EncodePassword(password)
	addRequest.Attribute("unicodePwd", []string{encodedPassword})

	// 执行创建
	client.Debug("执行创建用户操作")
	if err := conn.Add(addRequest); err != nil {
		return errors.New("创建用户失败: " + err.Error())
	}

	client.Info("成功创建用户: %s (启用状态)", userDN)
	return nil
}

// CreateOrUpdateUser 创建或更新用户
func (client *LDAPClient) CreateOrUpdateUser(userDN string, userName string, password string, isSSL bool) error {
	client.Debug("开始创建/更新用户：%s", userDN)
	if isSSL {
		// SSL模式：创建启用账号并设置密码
		return client.CreateUserWithSSL(userDN, userName, password, client.Host, nil)
	} else {
		// 非SSL模式：创建禁用账号
		return client.CreateUserWithoutSSL(userDN, userName, client.Host)
	}
}

// MoveUserToNewLocation 移动用户到新位置
func (client *LDAPClient) MoveUserToNewLocation(currentDN string, targetDN string) error {
	// 确保连接有效
	if err := client.EnsureConnection(); err != nil {
		return errors.New("连接失败: " + err.Error())
	}

	// 确保目标路径存在
	parentDN := strings.SplitN(targetDN, ",", 2)[1]
	if err := client.EnsureDNExists(parentDN); err != nil {
		return errors.New("创建目标路径失败: " + ParseLDAPError(err))
	}

	// 执行移动操作
	if err := client.MoveUser(currentDN, targetDN); err != nil {
		return errors.New("移动用户失败: " + ParseLDAPError(err))
	}

	return nil
}
