package ldap

import (
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// EncodePassword 将密码编码为LDAP所需的格式
func EncodePassword(password string) string {
	// 添加双引号包装密码
	quotedPassword := `"` + password + `"`

	// 将密码转换为UTF-16LE编码
	utf16Chars := utf16.Encode([]rune(quotedPassword))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, char := range utf16Chars {
		bytes[i*2] = byte(char)
		bytes[i*2+1] = byte(char >> 8)
	}
	return string(bytes)
}

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
	// 分割DN字符串
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return ""
	}

	// 获取第一部分（通常是CN=username）
	firstPart := parts[0]
	if !strings.HasPrefix(strings.ToUpper(firstPart), "CN=") {
		return ""
	}

	// 返回CN=后面的部分
	return strings.TrimPrefix(firstPart, "CN=")
}

// MoveUser 移动用户到新位置
func (client *LDAPClient) MoveUser(oldDN, newDN string) error {
	// 获取有效连接
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	// 分解新旧DN
	oldParts := strings.SplitN(oldDN, ",", 2)
	newParts := strings.SplitN(newDN, ",", 2)
	if len(oldParts) != 2 || len(newParts) != 2 {
		return fmt.Errorf("无效的DN格式")
	}

	// 提取新旧RDN和新的父DN
	newRDN := newParts[0]
	newSuperior := newParts[1]

	// 执行移动操作
	modifyDNRequest := ldap.NewModifyDNRequest(oldDN, newRDN, true, newSuperior)
	if err := conn.ModifyDN(modifyDNRequest); err != nil {
		return err
	}

	return nil
}

// ParseLDAPError 解析LDAP错误
func ParseLDAPError(err error) string {
	if err == nil {
		return ""
	}

	// 检查是否是LDAP错误
	if ldapErr, ok := err.(*ldap.Error); ok {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInsufficientAccessRights:
			return "权限不足"
		case ldap.LDAPResultEntryAlreadyExists:
			return "对象已存在"
		case ldap.LDAPResultNoSuchObject:
			return "对象不存在"
		case ldap.LDAPResultBusy:
			return "服务器忙"
		case ldap.LDAPResultOperationsError:
			return "操作错误"
		case ldap.LDAPResultInvalidCredentials:
			return "凭据无效"
		case ldap.LDAPResultInvalidDNSyntax:
			return "DN语法无效"
		case ldap.LDAPResultUnwillingToPerform:
			return "服务器拒绝执行"
		default:
			return "LDAP错误 (代码 " + string(rune(ldapErr.ResultCode)) + "): " + ldapErr.Error()
		}
	}

	// 其他类型的错误
	return err.Error()
}

// UpdateUserPassword 更新用户密码
func (client *LDAPClient) UpdateUserPassword(userDN string, newPassword string) error {
	// 获取有效连接
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(userDN, nil)

	// 将密码转换为UTF-16LE格式
	utf16Password := EncodePassword(newPassword)

	// 替换密码属性
	modifyRequest.Replace("unicodePwd", []string{utf16Password})

	// 执行修改
	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("更新密码失败: %v", err)
	}

	return nil
}

// HandleGroupMembership 处理用户的组成员关系
func (client *LDAPClient) HandleGroupMembership(userDN string, groupDN string) error {
	// 获取有效连接
	if err := client.EnsureConnection(); err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	// 添加到新组
	if err := client.AddUserToGroup(userDN, groupDN); err != nil {
		return fmt.Errorf("添加用户到组失败: %v", err)
	}

	return nil
}

// BuildDN 构建完整的DN
func (client *LDAPClient) BuildDN(parts []string) string {
	var currentDN string
	for i, part := range parts {
		if i > 0 {
			currentDN += ","
		}
		currentDN += part
		client.Debug("已创建DN部分: %s", currentDN)
	}
	return currentDN
}

// CreateDN 创建DN
func (client *LDAPClient) CreateDN(dn string) error {
	client.Debug("正在创建DN：%s", dn)
	// 确保连接有效
	conn, err := client.GetConnection()
	if err != nil {
		return fmt.Errorf("创建DN时连接失败: %v", err)
	}

	// 解析DN
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return fmt.Errorf("无效的DN格式：%s", dn)
	}

	// 创建DN的各个部分
	for i := len(parts) - 1; i >= 0; i-- {
		currentDN := strings.Join(parts[i:], ",")
		client.Debug("正在创建DN部分：%s", currentDN)

		// 构建添加请求
		add := ldap.NewAddRequest(currentDN, nil)
		add.Attribute("objectClass", []string{"container"})

		// 执行添加
		if err := conn.Add(add); err != nil {
			if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == 68 {
				// 已存在，继续下一个
				client.Debug("DN部分已存在：%s", currentDN)
				continue
			}
			return fmt.Errorf("创建DN部分失败: %v", err)
		}

		client.Debug("成功创建DN部分：%s", currentDN)
	}

	client.Info("成功创建完整DN：%s", dn)
	return nil
}
