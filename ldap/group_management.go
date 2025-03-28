package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// ACL权限常量
const (
	// 常用 Active Directory 权限掩码
	RIGHT_DS_READ_PROPERTY  uint32 = 0x00000010
	RIGHT_DS_WRITE_PROPERTY uint32 = 0x00000020
	RIGHT_DS_LIST_CONTENTS  uint32 = 0x00000004
	RIGHT_DS_LIST_OBJECT    uint32 = 0x00000080

	// 访问控制项类型
	ACCESS_ALLOWED_ACE_TYPE byte = 0x00
	ACCESS_DENIED_ACE_TYPE  byte = 0x01

	// ACE标志
	CONTAINER_INHERIT_ACE byte = 0x02
	INHERIT_ONLY_ACE      byte = 0x08
	OBJECT_INHERIT_ACE    byte = 0x01

	// 安全描述符控制标志
	DACL_SECURITY_INFORMATION uint32 = 0x00000004
)

// SetGroupACL 为组设置完整ACL
func (client *LDAPClient) SetGroupACL(groupDN string, attributes map[string][]string) error {
	conn, err := client.GetConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)

	// 添加或替换所有属性
	for name, values := range attributes {
		modifyRequest.Replace(name, values)
	}

	// 执行LDAP修改
	return conn.Modify(modifyRequest)
}

// EnsureDNExists 确保DN存在
func (client *LDAPClient) EnsureDNExists(dn string) error {
	client.Debug("正在检查DN是否存在：%s", dn)
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("检查DN时连接失败: %v", err)
	}

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		dn,                                             // 基准DN
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, // 搜索范围和别名处理
		0, 0, false, // 大小限制，时间限制，仅类型
		"(objectClass=*)", // 过滤器
		[]string{"dn"},    // 返回属性
		nil,               // 控制
	)

	// 执行搜索
	_, err = conn.Search(searchRequest)
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == 32 {
			// DN不存在，需要创建
			client.Debug("DN不存在，正在创建：%s", dn)
			return client.CreateDN(dn)
		}
		return fmt.Errorf("检查DN失败: %v", err)
	}

	client.Debug("DN已存在：%s", dn)
	return nil
}

// GetGroupMembers 获取组成员列表
func (client *LDAPClient) GetGroupMembers(groupDN string) ([]string, error) {
	client.Debug("正在获取组成员列表：%s", groupDN)
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return nil, fmt.Errorf("获取组成员时连接失败: %v", err)
	}

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		groupDN,                                        // 基准DN
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, // 搜索范围和别名处理
		0, 0, false, // 大小限制，时间限制，仅类型
		"(objectClass=group)", // 过滤器
		[]string{"member"},    // 返回属性
		nil,                   // 控制
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("搜索组失败: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("未找到组：%s", groupDN)
	}

	// 获取成员列表
	members := sr.Entries[0].GetAttributeValues("member")
	client.Debug("找到 %d 个组成员", len(members))
	return members, nil
}

// AddUserToGroup 添加用户到组
func (client *LDAPClient) AddUserToGroup(userDN string, groupDN string) error {
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Add("member", []string{userDN})

	// 执行修改
	if err := conn.Modify(modifyRequest); err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == 68 {
			// 用户已经是组成员，忽略错误
			return nil
		}
		return fmt.Errorf("添加用户到组失败: %v", err)
	}

	return nil
}

// RemoveUserFromAllGroups 从所有组中移除用户
func (client *LDAPClient) RemoveUserFromAllGroups(userDN string, searchDN string) error {
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 搜索包含该用户的所有组
	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=group)(member=%s))", ldap.EscapeFilter(userDN)),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("搜索组失败: %v", err)
	}

	// 从每个组中移除用户
	for _, entry := range sr.Entries {
		modifyRequest := ldap.NewModifyRequest(entry.DN, nil)
		modifyRequest.Delete("member", []string{userDN})
		if err := conn.Modify(modifyRequest); err != nil {
			client.Warn("从组 %s 移除用户失败: %v", entry.DN, err)
		}
	}

	return nil
}

// SearchGroup 搜索组
func (client *LDAPClient) SearchGroup(groupName string, searchDN string) (bool, string) {
	conn, err := client.GetConnection()
	if err != nil {
		client.Error("搜索组时连接失败: %v", err)
		return false, ""
	}

	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName)),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		client.Error("搜索组失败: %v", err)
		return false, ""
	}

	if len(sr.Entries) > 0 {
		return true, sr.Entries[0].DN
	}

	return false, ""
}

// ModifyGroup 修改组属性
func (client *LDAPClient) ModifyGroup(groupDN string, attributes map[string][]string) error {
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)

	// 添加或替换所有属性
	for name, values := range attributes {
		modifyRequest.Replace(name, values)
	}

	// 执行修改
	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("修改组属性失败: %v", err)
	}

	return nil
}

// ConfigureGroupForSSO 配置组的SSO权限
func (client *LDAPClient) ConfigureGroupForSSO(groupDN string, searchDN string) error {
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 设置组属性
	attributes := map[string][]string{
		"groupType":   {"-2147483646"}, // 安全组
		"description": {"SSO Authentication Group"},
	}

	if err := client.ModifyGroup(groupDN, attributes); err != nil {
		return fmt.Errorf("配置组属性失败: %v", err)
	}

	return nil
}

// CreateGroup 创建新组
func (client *LDAPClient) CreateGroup(groupDN string, groupName string) error {
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 创建组请求
	addRequest := ldap.NewAddRequest(groupDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "group"})
	addRequest.Attribute("cn", []string{groupName})
	addRequest.Attribute("groupType", []string{"-2147483646"}) // 安全组
	addRequest.Attribute("description", []string{"LDAP Authentication Group"})

	// 执行创建
	if err := conn.Add(addRequest); err != nil {
		return fmt.Errorf("创建组失败: %v", err)
	}

	return nil
}
