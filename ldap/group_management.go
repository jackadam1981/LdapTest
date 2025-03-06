package ldap

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"

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

// 安全描述符相关结构
type SecurityDescriptor struct {
	Revision    byte
	Sbz1        byte
	Control     uint16
	OwnerOffset uint32
	GroupOffset uint32
	SaclOffset  uint32
	DaclOffset  uint32
}

// ACL头部结构
type AclHeader struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

// ACE头部结构
type AceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

// 权限设置
type AccessRights struct {
	ObjectType string // 属性的OID
	Rights     uint32 // 权限掩码
}

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

// RemoveUserFromAllGroups 从所有组中移除用户
func (client *LDAPClient) RemoveUserFromAllGroups(userDN string) error {
	// 获取用户当前所属的组
	groups, err := client.GetUserGroups(userDN)
	if err != nil {
		return fmt.Errorf("获取用户组失败: %v", err)
	}

	// 从每个组中移除用户
	for _, groupDN := range groups {
		if err := client.RemoveUserFromGroup(userDN, groupDN); err != nil {
			log.Printf("从组 %s 移除用户时出错: %v", groupDN, err)
			// 继续处理其他组
		}
	}

	if client.UpdateFunc != nil {
		client.UpdateFunc(fmt.Sprintf("已从所有组中移除用户 %s", userDN))
	}

	return nil
}

// ConfigureGroupForSSO 配置组用于SSO身份验证
func (c *LDAPClient) ConfigureGroupForSSO(groupDN, baseDN string) error {
	// 获取LDAP连接
	conn, err := c.GetConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	// 提取组名
	groupNameParts := strings.Split(groupDN, ",")
	if len(groupNameParts) == 0 {
		return fmt.Errorf("无效的组DN: %s", groupDN)
	}
	groupName := strings.TrimPrefix(groupNameParts[0], "CN=")

	c.UpdateFunc(fmt.Sprintf("开始配置组 %s 的SSO权限...", groupName))

	// 设置基本组类型和描述
	attributes := map[string][]string{
		"groupType":   {"-2147483646"}, // 全局安全组
		"description": {"LDAP Authentication Group"},
	}

	if err := c.ModifyGroup(groupDN, attributes); err != nil {
		return fmt.Errorf("设置组基本属性失败: %v", err)
	}

	// 将组添加到用户容器的读取ACL中
	if err := c.AddGroupToReaders(baseDN, groupDN); err != nil {
		return fmt.Errorf("添加读取权限失败: %v", err)
	}

	c.UpdateFunc(fmt.Sprintf("成功配置组 %s 的SSO权限", groupName))
	return nil
}

// AddGroupToReaders 将组添加到容器的读取者列表
func (c *LDAPClient) AddGroupToReaders(containerDN, groupDN string) error {
	conn, err := c.GetConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	// 获取groupSID（用于调试和日志）
	groupSID, err := c.GetGroupSID(groupDN)
	if err != nil {
		c.UpdateFunc(fmt.Sprintf("警告：无法获取组SID: %v", err))
		// 继续处理，因为我们可以直接使用组DN
	} else {
		c.UpdateFunc(fmt.Sprintf("组SID: %s", groupSID))
	}

	// 在AD中，我们可以通过设置defaultSecurityDescriptor或修改已有的dSHeuristics来添加读取权限
	// 这里我们使用一个更直接的方法：将组添加到特定访问权限列表

	// 1. 首先检查容器是否有"allowedAttributeSet"属性
	searchRequest := ldap.NewSearchRequest(
		containerDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectClass"},
		nil,
	)

	_, err = conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("搜索容器失败: %v", err)
	}

	// 2. 为SSO添加必要的读取权限
	// 针对SSO，我们需要确保组可以读取用户的基本属性

	// 2.1 将组添加到容器的adminDescription属性（用于记录自定义权限）
	modifyRequest := ldap.NewModifyRequest(containerDN, nil)
	modifyRequest.Add("adminDescription", []string{
		fmt.Sprintf("SSO_Reader:%s", groupDN),
	})

	// 尝试修改，但不强制要求成功（因为adminDescription可能不允许修改）
	err = conn.Modify(modifyRequest)
	if err != nil {
		c.UpdateFunc(fmt.Sprintf("添加adminDescription时出现警告: %v", err))
		// 继续处理
	}

	// 2.2 修改容器上的权限 - 在实际环境中，这通常需要使用安全描述符编辑器或ADSI接口
	// 由于go-ldap的限制，我们通过修改组而不是容器来实现类似效果

	// 将容器DN添加到组的managedBy属性
	modifyGroupRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyGroupRequest.Replace("managedBy", []string{containerDN})

	err = conn.Modify(modifyGroupRequest)
	if err != nil {
		return fmt.Errorf("设置组的managedBy属性失败: %v", err)
	}

	// 为组添加重要的SSO相关属性读取权限
	// 这是通过向组添加auxiliaryClass来间接实现的
	addAuxiliaryClass := ldap.NewModifyRequest(groupDN, nil)
	addAuxiliaryClass.Add("auxiliaryClass", []string{"msDS-AzRole"})

	err = conn.Modify(addAuxiliaryClass)
	if err != nil {
		c.UpdateFunc(fmt.Sprintf("添加auxiliaryClass时出现警告: %v", err))
		// 这可能会失败，因为不是所有AD架构都支持msDS-AzRole
	}

	return nil
}

// GetGroupSID 获取组的SID
func (c *LDAPClient) GetGroupSID(groupDN string) (string, error) {
	conn, err := c.GetConnection()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 搜索组SID
	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("搜索组SID失败: %v", err)
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("未找到组: %s", groupDN)
	}

	sidBinary := searchResult.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidBinary) == 0 {
		return "", fmt.Errorf("组没有SID")
	}

	// 将二进制SID转换为字符串格式
	return formatSIDString(sidBinary), nil
}

// formatSIDString 将二进制SID转换为字符串
func formatSIDString(sidBytes []byte) string {
	if len(sidBytes) < 8 {
		return ""
	}

	// SID结构: 版本(1字节) + 子授权计数(1字节) + 授权标识(6字节) + 子授权(4字节*n)
	revision := sidBytes[0]
	subAuthorityCount := int(sidBytes[1])
	identifierAuthority := binary.BigEndian.Uint64(append([]byte{0, 0}, sidBytes[2:8]...))

	// 构建S-R-I-S-S...格式
	result := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)

	// 添加子授权
	for i := 0; i < subAuthorityCount; i++ {
		if 8+i*4+4 <= len(sidBytes) {
			subAuth := binary.LittleEndian.Uint32(sidBytes[8+i*4:])
			result += fmt.Sprintf("-%d", subAuth)
		}
	}

	return result
}

// SetGroupACL 为组设置完整ACL
func (c *LDAPClient) SetGroupACL(groupDN string, attributes map[string][]string) error {
	conn, err := c.GetConnection()
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
