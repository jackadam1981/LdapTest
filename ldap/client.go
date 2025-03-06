// Package ldap 提供LDAP客户端功能
package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPClient 是LDAP客户端结构体
type LDAPClient struct {
	Host         string       // LDAP服务器地址（IP或域名）
	Port         int          // LDAP服务端口（默认389）
	BindDN       string       // 绑定用识别名（用于认证的Distinguished Name）
	BindPassword string       // 绑定用密码
	UpdateFunc   func(string) // 添加状态更新函数引用
	Conn         *ldap.Conn   // LDAP连接实例
	UseTLS       bool         // 是否使用TLS/SSL
}

// GetURL 返回LDAP服务器的URL
func (client *LDAPClient) GetURL() string {
	protocol := "ldap"
	if client.UseTLS {
		protocol = "ldaps"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, client.Host, client.Port)
}

// Connect 连接到LDAP服务器
func (client *LDAPClient) Connect() error {
	var err error

	// 记录连接URL
	log.Printf("正在连接到 %s", client.GetURL())
	if client.UpdateFunc != nil {
		client.UpdateFunc(fmt.Sprintf("正在连接到 %s", client.GetURL()))
	}

	// 使用net.JoinHostPort处理IPv4和IPv6地址
	address := net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))

	// 根据TLS设置选择连接方式
	if client.UseTLS {
		// 使用TLS配置
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // 测试环境下允许跳过证书验证
		}
		client.Conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		// 使用普通LDAP连接
		client.Conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return fmt.Errorf("连接LDAP服务器失败: %v", err)
	}

	// 设置超时
	client.Conn.SetTimeout(5 * time.Second)

	return nil
}

// Bind 绑定到LDAP服务器
func (client *LDAPClient) Bind(bindDN, bindPassword string) error {
	if client.Conn == nil {
		return fmt.Errorf("未连接到LDAP服务器")
	}

	return client.Conn.Bind(bindDN, bindPassword)
}

// Close 关闭LDAP连接
func (client *LDAPClient) Close() {
	if client.Conn != nil {
		client.Conn.Close()
		client.Conn = nil
	}
}

// BindWithRetry 带重试的绑定操作
func (client *LDAPClient) BindWithRetry(bindDN, bindPassword string) error {
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// 检查连接状态
		if client.Conn == nil {
			if err := client.Connect(); err != nil {
				lastErr = err
				log.Printf("连接失败 (尝试 %d/%d): %v", attempt, maxRetries, err)
				continue
			}
		}

		// 尝试绑定
		if err := client.Conn.Bind(bindDN, bindPassword); err != nil {
			lastErr = err
			log.Printf("绑定失败 (尝试 %d/%d): %v", attempt, maxRetries, err)

			// 检查是否是连接错误
			if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == 200 {
				// 连接错误，关闭连接并重试
				client.Close()
				continue
			}

			// 其他错误直接返回
			return err
		}

		// 绑定成功
		return nil
	}

	return fmt.Errorf("绑定失败，已重试%d次: %v", maxRetries, lastErr)
}

// IsPortOpen 检查LDAP端口是否开放
func (client *LDAPClient) IsPortOpen() bool {
	// 使用net.JoinHostPort来正确处理IPv4和IPv6地址
	address := net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		log.Printf("端口检查失败: %v", err)
		return false
	}
	defer conn.Close()
	return true
}

// TestLDAPService 测试LDAP服务是否正常
func (client *LDAPClient) TestLDAPService() bool {
	// 先检查端口
	if !client.IsPortOpen() {
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("端口 %d 未开放", client.Port))
		}
		return false
	}

	// 尝试连接
	if err := client.Connect(); err != nil {
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("连接失败: %v", err))
		}
		return false
	}
	defer client.Close()

	// 尝试绑定
	if err := client.Bind(client.BindDN, client.BindPassword); err != nil {
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("绑定失败: %v", err))
		}
		return false
	}

	// 连接和绑定都成功
	if client.UpdateFunc != nil {
		client.UpdateFunc("LDAP服务正常")
	}
	return true
}

// IsConnectionValid 检查LDAP连接是否有效
func (client *LDAPClient) IsConnectionValid() bool {
	// 检查连接是否为nil
	if client.Conn == nil {
		return false
	}

	// 尝试执行轻量级搜索操作来验证连接
	searchRequest := ldap.NewSearchRequest(
		"", // 空DN，执行rootDSE搜索
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 3, false,
		"(objectClass=*)",
		[]string{"supportedLDAPVersion"},
		nil,
	)

	_, err := client.Conn.Search(searchRequest)

	// 如果发生错误，检查是否是连接错误
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok {
			// ResultCode 200表示网络错误，通常意味着连接已关闭
			if ldapErr.ResultCode == 200 {
				return false
			}
		}
		// 其他类型的错误也可能表明连接有问题
		return false
	}

	// 搜索成功，说明连接有效
	return true
}

// EnsureConnection 确保LDAP连接有效，如果无效则尝试重新连接
func (client *LDAPClient) EnsureConnection() error {
	if client == nil {
		return fmt.Errorf("LDAP客户端对象为空")
	}

	// 检查现有连接是否有效
	if client.IsConnectionValid() {
		// 连接有效，无需操作
		return nil
	}

	// 连接无效，需要重新连接
	if client.UpdateFunc != nil {
		client.UpdateFunc("检测到连接已关闭，正在重新连接...")
	}

	// 关闭现有连接（如果存在）
	client.Close()

	// 尝试重新连接
	if err := client.Connect(); err != nil {
		if client.UpdateFunc != nil {
			client.UpdateFunc(fmt.Sprintf("重新连接失败: %v", err))
		}
		return fmt.Errorf("重新连接失败: %v", err)
	}

	// 如果之前已经绑定过（有bindDN），尝试重新绑定
	if client.BindDN != "" && client.BindPassword != "" {
		if err := client.Bind(client.BindDN, client.BindPassword); err != nil {
			if client.UpdateFunc != nil {
				client.UpdateFunc(fmt.Sprintf("重新绑定失败: %v", err))
			}
			return fmt.Errorf("重新绑定失败: %v", err)
		}
	}

	if client.UpdateFunc != nil {
		client.UpdateFunc("重新连接成功")
	}
	return nil
}

// GetConnection 返回有效的LDAP连接，如果连接无效会自动重连
func (client *LDAPClient) GetConnection() (*ldap.Conn, error) {
	if err := client.EnsureConnection(); err != nil {
		return nil, err
	}
	return client.Conn, nil
}

// Shutdown 关闭LDAP连接并释放资源
func (client *LDAPClient) Shutdown() {
	client.Close()
}
