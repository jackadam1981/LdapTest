package ldap

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// SearchGroup 在域中搜索组
func (client *LDAPClient) SearchGroup(groupName, searchDN string) (bool, string) {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		log.Printf("搜索组时连接失败: %v", err)
		return false, ""
	}

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName)),
		[]string{"dn"},
		nil,
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("搜索组失败: %v", err)
		return false, ""
	}

	// 检查是否找到组
	if len(sr.Entries) > 0 {
		return true, sr.Entries[0].DN
	}

	return false, ""
}

// CreateGroup 创建新的组
func (client *LDAPClient) CreateGroup(groupDN, groupName string) error {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("创建组时连接失败: %v", err)
	}

	// 确保父DN存在
	parentDN := strings.SplitN(groupDN, ",", 2)[1]
	if err := client.EnsureDNExists(parentDN); err != nil {
		return fmt.Errorf("确保父DN存在失败: %v", err)
	}

	// 创建组请求
	addRequest := ldap.NewAddRequest(groupDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "group"})
	addRequest.Attribute("groupType", []string{"-2147483646"}) // 全局安全组
	addRequest.Attribute("sAMAccountName", []string{groupName})

	// 执行创建
	if err := conn.Add(addRequest); err != nil {
		return fmt.Errorf("创建组失败: %v", err)
	}

	if client.UpdateFunc != nil {
		client.UpdateFunc(fmt.Sprintf("成功创建组: %s", groupDN))
	}

	return nil
}

// ModifyGroup 修改组属性
func (client *LDAPClient) ModifyGroup(groupDN string, attributes map[string][]string) error {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("修改组时连接失败: %v", err)
	}

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)

	// 添加属性
	for attr, values := range attributes {
		modifyRequest.Replace(attr, values)
	}

	// 执行修改
	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("修改组失败: %v", err)
	}

	if client.UpdateFunc != nil {
		client.UpdateFunc(fmt.Sprintf("成功修改组: %s", groupDN))
	}

	return nil
}

// AddUserToGroup 将用户添加到组
func (client *LDAPClient) AddUserToGroup(userDN, groupDN string) error {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("添加用户到组时连接失败: %v", err)
	}

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Add("member", []string{userDN})

	// 执行修改
	if err := conn.Modify(modifyRequest); err != nil {
		// 忽略"已存在"错误
		if ldapErr, ok := err.(*ldap.Error); !ok || ldapErr.ResultCode != ldap.LDAPResultEntryAlreadyExists {
			return fmt.Errorf("添加用户到组失败: %v", err)
		}
	}

	if client.UpdateFunc != nil {
		client.UpdateFunc(fmt.Sprintf("已将用户 %s 添加到组 %s", userDN, groupDN))
	}

	return nil
}

// RemoveUserFromGroup 从组中移除用户
func (client *LDAPClient) RemoveUserFromGroup(userDN, groupDN string) error {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("从组中移除用户时连接失败: %v", err)
	}

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Delete("member", []string{userDN})

	// 执行修改
	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("从组中移除用户失败: %v", err)
	}

	if client.UpdateFunc != nil {
		client.UpdateFunc(fmt.Sprintf("已从组 %s 移除用户 %s", groupDN, userDN))
	}

	return nil
}

// GetUserGroups 获取用户所属的组
func (client *LDAPClient) GetUserGroups(userDN string) ([]string, error) {
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return nil, fmt.Errorf("获取用户组时连接失败: %v", err)
	}

	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=user)",
		[]string{"memberOf"},
		nil,
	)

	// 执行搜索
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("搜索用户组失败: %v", err)
	}

	// 检查是否找到用户
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("未找到用户: %s", userDN)
	}

	// 获取组列表
	return sr.Entries[0].GetAttributeValues("memberOf"), nil
}
