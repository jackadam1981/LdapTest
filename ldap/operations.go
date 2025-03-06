package ldap

import (
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
		{Name: "sAMAccountName", Pattern: "(&(objectClass=user)(sAMAccountName=%s))"},
		{Name: "userPrincipalName", Pattern: "(&(objectClass=user)(userPrincipalName=%s))"},
		{Name: "mail", Pattern: "(&(objectClass=user)(mail=%s))"},
		{Name: "distinguishedName", Pattern: "(&(objectClass=user)(distinguishedName=%s))"},
		{Name: "cn", Pattern: "(&(objectClass=user)(cn=%s))"},
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
