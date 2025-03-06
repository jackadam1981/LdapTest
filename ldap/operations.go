package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPFilter 定义LDAP过滤器结构
type LDAPFilter struct {
	Name    string // 过滤器名称
	Pattern string // 过滤器模式
}

// CommonFilters 返回常用的LDAP过滤器列表
func CommonFilters() []LDAPFilter {
	return []LDAPFilter{
		{Name: "用户名模式:sAMAccountName", Pattern: "(&(objectClass=user)(sAMAccountName=%s))"},
		{Name: "用户邮箱格式:userPrincipalName", Pattern: "(&(objectClass=user)(userPrincipalName=%s))"},
		{Name: "用户邮箱:mail", Pattern: "(&(objectClass=user)(mail=%s))"},
		{Name: "OpenLDAP模式:distinguishedName", Pattern: "(&(objectClass=user)(distinguishedName=%s))"},
		{Name: "通用模式:cn", Pattern: "(&(objectClass=user)(cn=%s))"},
	}
}

// ExtractUsernameFromDN 从DN中提取用户名
func ExtractUsernameFromDN(dn string) string {
	// 从DN中提取CN部分
	parts := strings.Split(dn, ",")
	if len(parts) > 0 {
		cnPart := parts[0]
		if strings.HasPrefix(strings.ToLower(cnPart), "cn=") {
			return strings.TrimPrefix(cnPart, "CN=")
		}
	}
	return dn
}

// EnsureDNExists 确保指定的DN路径存在
func (client *LDAPClient) EnsureDNExists(targetDN string) error {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("确保DN存在时连接失败: %v", err)
	}

	// 检查DN是否已存在
	searchRequest := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = conn.Search(searchRequest)
	if err == nil {
		// DN已存在，无需创建
		return nil
	}

	// 如果错误不是"找不到条目"，则返回错误
	if ldapErr, ok := err.(*ldap.Error); !ok || ldapErr.ResultCode != ldap.LDAPResultNoSuchObject {
		return fmt.Errorf("检查DN存在性失败: %v", err)
	}

	// DN不存在，需要创建
	// 分解DN，从最上层开始检查和创建
	parts := strings.Split(targetDN, ",")
	if len(parts) <= 1 {
		return fmt.Errorf("无效的DN格式: %s", targetDN)
	}

	// 从倒数第二个部分开始，逐级向下创建
	for i := len(parts) - 2; i >= 0; i-- {
		currentDN := strings.Join(parts[i:], ",")

		// 检查当前级别是否存在
		searchRequest := ldap.NewSearchRequest(
			currentDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		)

		_, err = conn.Search(searchRequest)
		if err == nil {
			// 当前级别存在，继续检查下一级
			continue
		}

		// 如果错误不是"找不到条目"，则返回错误
		if ldapErr, ok := err.(*ldap.Error); !ok || ldapErr.ResultCode != ldap.LDAPResultNoSuchObject {
			return fmt.Errorf("检查DN级别存在性失败: %v", err)
		}

		// 当前级别不存在，需要创建
		// 解析当前部分的类型和名称
		currentPart := parts[i]
		if !strings.Contains(currentPart, "=") {
			return fmt.Errorf("无效的DN部分: %s", currentPart)
		}

		partType := strings.Split(currentPart, "=")[0]
		partName := strings.Split(currentPart, "=")[1]

		// 创建请求
		addRequest := ldap.NewAddRequest(currentDN, nil)

		// 根据类型设置对象类
		switch strings.ToLower(partType) {
		case "cn":
			addRequest.Attribute("objectClass", []string{"container"})
			addRequest.Attribute("cn", []string{partName})
		case "ou":
			addRequest.Attribute("objectClass", []string{"organizationalUnit"})
			addRequest.Attribute("ou", []string{partName})
		default:
			return fmt.Errorf("不支持的DN部分类型: %s", partType)
		}

		// 执行创建
		if err := conn.Add(addRequest); err != nil {
			return fmt.Errorf("创建DN部分失败: %v", err)
		}

		log.Printf("已创建DN部分: %s", currentDN)
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("已创建路径: %s", currentDN))
		}
	}

	return nil
}

// MoveUser 移动用户或组到新位置
func (client *LDAPClient) MoveUser(oldDN, newDN string) error {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("移动用户时连接失败: %v", err)
	}

	// 解析新旧DN
	oldParts := strings.SplitN(oldDN, ",", 2)
	newParts := strings.SplitN(newDN, ",", 2)

	if len(oldParts) < 2 || len(newParts) < 2 {
		return fmt.Errorf("无效的DN格式")
	}

	// 提取RDN和父DN
	oldRDN := oldParts[0]
	newParentDN := newParts[1]

	// 确保目标父DN存在
	if err := client.EnsureDNExists(newParentDN); err != nil {
		return fmt.Errorf("确保目标路径存在失败: %v", err)
	}

	// 执行移动操作
	modifyDNRequest := ldap.NewModifyDNRequest(oldDN, oldRDN, true, newParentDN)
	if err := conn.ModifyDN(modifyDNRequest); err != nil {
		return fmt.Errorf("移动操作失败: %v", err)
	}

	return nil
}

// ParseLDAPError 解析LDAP错误，返回友好的中文提示
func ParseLDAPError(err error) string {
	if err == nil {
		return ""
	}

	errMsg := err.Error()

	// 解析LDAP错误代码
	if strings.Contains(errMsg, "LDAP Result Code 53") {
		// 不愿执行操作错误
		if strings.Contains(errMsg, "0000001F") || strings.Contains(errMsg, "001F") {
			return "权限不足，无法执行操作 (Code 53: 0000001F)"
		}
		// 策略限制
		if strings.Contains(errMsg, "0000052D") || strings.Contains(errMsg, "052D") {
			return "违反密码策略，密码不符合复杂性要求 (Code 53: 0000052D)"
		}
		// 其他不愿执行操作错误
		return "服务器拒绝执行操作 (Code 53: Unwilling To Perform)"
	}

	// 解析其他常见错误
	if strings.Contains(errMsg, "LDAP Result Code 49") {
		return "认证失败，用户名或密码错误 (Code 49)"
	}
	if strings.Contains(errMsg, "LDAP Result Code 32") {
		return "对象不存在 (Code 32)"
	}
	if strings.Contains(errMsg, "LDAP Result Code 68") {
		return "条目已存在 (Code 68)"
	}

	// 默认返回原始错误信息
	return errMsg
}

// UpdateUserPassword 更新用户密码
func (client *LDAPClient) UpdateUserPassword(userDN string, newPassword string) error {
	log.Printf("[DEBUG] 开始更新用户密码，用户DN: %s", userDN)

	// 创建SSL连接
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	updateConn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", client.Host, client.Port), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return fmt.Errorf("创建密码更新连接失败: %v", err)
	}
	defer updateConn.Close()

	// 管理员绑定
	if err := updateConn.Bind(client.BindDN, client.BindPassword); err != nil {
		return fmt.Errorf("密码更新绑定失败: %v", err)
	}

	// 创建密码修改请求
	modifyRequest := ldap.NewModifyRequest(userDN, nil)

	// 编码并设置密码
	encodedPassword := EncodePassword(newPassword)
	modifyRequest.Replace("unicodePwd", []string{encodedPassword})
	modifyRequest.Replace("userAccountControl", []string{"512"})

	// 执行修改
	if err := updateConn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("更新密码失败: %s", ParseLDAPError(err))
	}

	return nil
}

// HandleGroupMembership 处理用户组成员关系
func (client *LDAPClient) HandleGroupMembership(userDN string, groupDN string) error {
	// 确保连接有效
	if err := client.EnsureConnection(); err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	// 先移除用户的所有组
	if err := client.RemoveUserFromAllGroups(userDN); err != nil {
		return fmt.Errorf("移除现有用户组失败: %v", err)
	}

	// 添加到新组
	if err := client.AddUserToGroup(userDN, groupDN); err != nil {
		return fmt.Errorf("添加用户到组失败: %v", err)
	}

	return nil
}

// CreateOrUpdateUser 创建或更新用户
func (client *LDAPClient) CreateOrUpdateUser(userDN string, userName string, password string, isSSL bool) error {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	// 确保父容器存在
	parentDN := strings.SplitN(userDN, ",", 2)[1]
	if err := client.EnsureDNExists(parentDN); err != nil {
		return fmt.Errorf("创建路径失败: %s", ParseLDAPError(err))
	}

	if isSSL {
		// SSL模式：创建启用账号并设置密码
		return CreateUserWithSSL(conn, client, userDN, userName, password, client.Host, nil, client.UpdateFunc)
	} else {
		// 非SSL模式：创建禁用账号
		return CreateUserWithoutSSL(conn, userDN, userName, client.Host, client.UpdateFunc)
	}
}

// MoveUserToNewLocation 移动用户到新位置
func (client *LDAPClient) MoveUserToNewLocation(currentDN string, targetDN string) error {
	// 确保连接有效
	if err := client.EnsureConnection(); err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	// 确保目标路径存在
	parentDN := strings.SplitN(targetDN, ",", 2)[1]
	if err := client.EnsureDNExists(parentDN); err != nil {
		return fmt.Errorf("创建目标路径失败: %s", ParseLDAPError(err))
	}

	// 执行移动操作
	if err := client.MoveUser(currentDN, targetDN); err != nil {
		return fmt.Errorf("移动用户失败: %s", ParseLDAPError(err))
	}

	return nil
}

// SearchUser 根据用户名搜索用户
func (client *LDAPClient) SearchUser(userName string, searchBase string) (bool, string) {
	// 获取有效连接
	conn, err := client.GetConnection()
	if err != nil {
		client.UpdateFunc(fmt.Sprintf("连接失败: %v", err))
		return false, ""
	}

	// 构建搜索请求，按CN进行模糊查询
	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(cn=%s))", ldap.EscapeFilter(userName)),
		[]string{"dn"},
		nil,
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		client.UpdateFunc(fmt.Sprintf("搜索失败: %v", err))
		return false, ""
	}

	// 检查是否找到用户
	if len(sr.Entries) > 0 {
		return true, sr.Entries[0].DN
	}

	return false, ""
}
