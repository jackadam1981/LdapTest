// Package ldap 提供LDAP客户端功能
package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
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
	Logger       interface {  // 日志记录器接口
		Debug(format string, args ...interface{})
		Info(format string, args ...interface{})
		Warn(format string, args ...interface{})
		Error(format string, args ...interface{})
	}
	Conn      *ldap.Conn // LDAP连接实例
	UseTLS    bool       // 是否使用TLS/SSL
	DebugMode bool       // 调试模式
}

// log 是一个内部辅助方法，根据日志级别记录消息
func (client *LDAPClient) log(level string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)

	// 如果设置了 Logger，优先使用
	if client.Logger != nil {
		switch level {
		case "DEBUG":
			client.Logger.Debug(format, args...)
		case "INFO":
			client.Logger.Info(format, args...)
		case "WARN":
			client.Logger.Warn(format, args...)
		case "ERROR":
			client.Logger.Error(format, args...)
		}
		return
	}

	// 如果没有设置 Logger，使用 UpdateFunc（兼容旧代码）
	if client.UpdateFunc != nil {
		client.UpdateFunc(msg)
	}
}

// Debug 记录调试级别消息
func (client *LDAPClient) Debug(format string, args ...interface{}) {
	client.log("DEBUG", format, args...)
}

// Info 记录信息级别消息
func (client *LDAPClient) Info(format string, args ...interface{}) {
	client.log("INFO", format, args...)
}

// Warn 记录警告级别消息
func (client *LDAPClient) Warn(format string, args ...interface{}) {
	client.log("WARN", format, args...)
}

// Error 记录错误级别消息
func (client *LDAPClient) Error(format string, args ...interface{}) {
	client.log("ERROR", format, args...)
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
	client.Info("正在连接到 %s", client.GetURL())

	// 根据TLS设置选择连接方式
	if client.UseTLS {
		// 使用TLS配置
		tlsConfig := &tls.Config{
			InsecureSkipVerify: client.DebugMode, // 仅在调试模式下跳过证书验证
			ServerName:         client.Host,
		}
		client.Conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))), ldap.DialWithTLSConfig(tlsConfig))
	} else {
		// 使用普通LDAP连接
		client.Conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))))
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
	protocol := "LDAP"
	if client.UseTLS {
		protocol = "LDAPS"
	}

	address := net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))
	client.Debug("正在检查 %s 端口 %d 是否开放...", protocol, client.Port)

	// 只使用TCP连接检查端口，不进行TLS握手
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)

	if err != nil {
		client.Warn("%s 端口 %d 未开放: %v", protocol, client.Port, err)
		return false
	}

	defer conn.Close()
	client.Info("%s 端口 %d 已开放", protocol, client.Port)
	return true
}

// TestLDAPService 测试LDAP服务是否正常
func (client *LDAPClient) TestLDAPService() bool {
	// 1. 首先检查端口是否开放
	protocol := "LDAP"
	if client.UseTLS {
		protocol = "LDAPS"
	}

	address := net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))
	client.Debug("正在检查 %s 端口 %d 是否开放...", protocol, client.Port)

	// 使用纯TCP连接检查端口
	tcpConn, tcpErr := net.DialTimeout("tcp", address, 3*time.Second)
	if tcpErr != nil {
		client.Warn("%s 端口 %d 未开放: %v", protocol, client.Port, tcpErr)
		return false
	}

	tcpConn.Close()
	client.Info("%s 端口 %d 已开放", protocol, client.Port)

	// 2. 然后检查LDAP服务
	client.Debug("正在测试 %s 服务...", protocol)

	var authConn *ldap.Conn
	var connErr error

	if client.UseTLS {
		// 配置TLS
		tlsConfig := &tls.Config{
			InsecureSkipVerify: client.DebugMode, // 仅在调试模式下跳过证书验证
			ServerName:         client.Host,
		}

		// 使用DialURL建立TLS连接
		client.Debug("尝试建立 LDAPS 安全连接并验证证书...")
		authConn, connErr = ldap.DialURL(fmt.Sprintf("ldaps://%s", address), ldap.DialWithTLSConfig(tlsConfig))

		if connErr != nil {
			// 检查是否是证书验证错误
			if strings.Contains(connErr.Error(), "certificate") ||
				strings.Contains(connErr.Error(), "x509") ||
				strings.Contains(connErr.Error(), "tls") {
				client.Error("LDAPS 证书验证失败: %v", connErr)
				client.Warn("请注意: 端口已开放，但 TLS 证书验证失败")
				client.Info("解决方案: 1.启用调试模式(跳过验证) 2.导入正确证书 3.检查证书名称")
				return false
			}
			client.Error("LDAPS 连接失败: %v", connErr)
			return false
		}

		client.Info("LDAPS 连接成功，证书验证通过")

		// 获取证书信息
		tlsConn, ok := authConn.TLSConnectionState()
		if ok && len(tlsConn.PeerCertificates) > 0 {
			cert := tlsConn.PeerCertificates[0]
			client.Debug("LDAPS 证书详细信息:")
			client.Debug("  - 证书主题: %s", cert.Subject.CommonName)
			if len(cert.DNSNames) > 0 {
				client.Debug("  - 证书域名: %v", cert.DNSNames)
			}
			client.Debug("  - 颁发者: %s", cert.Issuer.CommonName)
			client.Debug("  - 有效期: %s 至 %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))

			// 检查证书是否即将过期（30天内）
			if time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter) {
				client.Warn("  - 警告: 证书即将过期！剩余 %d 天", int(cert.NotAfter.Sub(time.Now()).Hours()/24))
			}
		}
	} else {
		// 使用DialURL建立普通连接
		client.Debug("尝试建立 LDAP 标准连接...")
		authConn, connErr = ldap.DialURL(fmt.Sprintf("ldap://%s", address))

		if connErr != nil {
			client.Error("LDAP 服务连接失败: %v", connErr)
			return false
		}

		client.Info("LDAP 服务连接成功")
	}

	defer authConn.Close()

	// 3. 最后尝试绑定验证身份
	client.Debug("正在验证账户 %s 凭据...", client.BindDN)
	bindErr := authConn.Bind(client.BindDN, client.BindPassword)
	if bindErr != nil {
		client.Error("账户认证失败: %v", bindErr)
		return false
	}

	// 成功总结
	if client.UseTLS {
		client.Info("LDAPS 测试结果: 端口已开放，TLS 证书有效，认证成功")
	} else {
		client.Info("LDAP 测试结果: 端口已开放，服务正常，认证成功")
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
	client.Warn("检测到连接已关闭，正在重新连接...")

	// 关闭现有连接（如果存在）
	client.Close()

	// 尝试重新连接
	if err := client.Connect(); err != nil {
		client.Error("重新连接失败: %v", err)
		return fmt.Errorf("重新连接失败: %v", err)
	}

	// 如果之前已经绑定过（有bindDN），尝试重新绑定
	if client.BindDN != "" && client.BindPassword != "" {
		if err := client.Bind(client.BindDN, client.BindPassword); err != nil {
			client.Error("重新绑定失败: %v", err)
			return fmt.Errorf("重新绑定失败: %v", err)
		}
	}

	client.Info("重新连接成功")
	return nil
}

// GetConnection 获取LDAP连接
func (client *LDAPClient) GetConnection() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	// 先检查端口是否开放
	address := net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))
	client.Debug("正在检查端口 %d 是否开放...", client.Port)

	// 使用纯TCP连接检查端口
	tcpConn, tcpErr := net.DialTimeout("tcp", address, 3*time.Second)
	if tcpErr != nil {
		client.Warn("端口 %d 未开放: %v", client.Port, tcpErr)
		return nil, fmt.Errorf("端口未开放: %v", tcpErr)
	}

	tcpConn.Close()
	client.Debug("端口 %d 已开放", client.Port)

	// 端口开放后，尝试建立LDAP连接
	client.Debug("正在连接LDAP服务器...")

	if client.UseTLS {
		// 配置TLS
		tlsConfig := &tls.Config{
			InsecureSkipVerify: client.DebugMode, // 仅在调试模式下跳过证书验证
			ServerName:         client.Host,
		}

		// 使用DialURL建立TLS连接
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", address), ldap.DialWithTLSConfig(tlsConfig))

		if err != nil {
			// 检查是否是证书验证错误
			if strings.Contains(err.Error(), "certificate") ||
				strings.Contains(err.Error(), "x509") ||
				strings.Contains(err.Error(), "tls") {
				client.Error("证书验证失败: %v", err)
				client.Info("请启用调试模式(跳过TLS验证)或导入正确的证书")
				return nil, fmt.Errorf("证书验证失败: %v", err)
			}
			client.Error("LDAP服务连接失败: %v", err)
			return nil, err
		}

		client.Info("TLS连接成功，证书验证通过")

		// 获取证书信息
		tlsConn, ok := conn.TLSConnectionState()
		if ok && len(tlsConn.PeerCertificates) > 0 {
			cert := tlsConn.PeerCertificates[0]
			client.Info("LDAPS 证书信息:")
			client.Info("  - 证书主题: %s", cert.Subject.CommonName)
			if len(cert.DNSNames) > 0 {
				client.Info("  - 证书域名: %v", cert.DNSNames)
			}
			client.Info("  - 颁发者: %s", cert.Issuer.CommonName)
			client.Info("  - 有效期: %s 至 %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))

			// 检查证书是否即将过期（30天内）
			if time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter) {
				client.Warn("  - 警告: 证书即将过期！剩余 %d 天", int(cert.NotAfter.Sub(time.Now()).Hours()/24))
			}
		}
	} else {
		// 使用DialURL建立普通连接
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", address))

		if err != nil {
			client.Error("LDAP服务连接失败: %v", err)
			return nil, err
		}

		client.Info("LDAP服务连接成功")
	}

	// 绑定到LDAP
	if client.BindDN != "" && client.BindPassword != "" {
		client.Debug("正在绑定用户 %s", client.BindDN)
		err = conn.Bind(client.BindDN, client.BindPassword)
		if err != nil {
			client.Error("绑定LDAP失败: %v", err)
			conn.Close()
			return nil, err
		}
		client.Info("绑定LDAP成功")
	}

	return conn, nil
}

// Shutdown 关闭LDAP连接并释放资源
func (client *LDAPClient) Shutdown() {
	client.Close()
}

// TestServiceConnection 测试LDAP服务连接（不包括绑定验证）
func (client *LDAPClient) TestServiceConnection() (*ldap.Conn, error) {
	// 定义变量但不初始化，由后面的条件语句设置
	var protocol string
	if client.UseTLS {
		protocol = "LDAPS"
	} else {
		protocol = "LDAP"
	}

	address := net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))
	client.Debug("开始测试 %s 服务连接", protocol)

	var conn *ldap.Conn
	var err error

	if client.UseTLS {
		// 配置TLS
		tlsConfig := &tls.Config{
			InsecureSkipVerify: client.DebugMode, // 仅在调试模式下跳过证书验证
			ServerName:         client.Host,
		}

		// 使用DialURL建立TLS连接
		client.Debug("尝试建立 LDAPS 安全连接并验证证书...")
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", address), ldap.DialWithTLSConfig(tlsConfig))

		if err != nil {
			// 检查是否是证书验证错误
			if strings.Contains(err.Error(), "certificate") ||
				strings.Contains(err.Error(), "x509") ||
				strings.Contains(err.Error(), "tls") {
				client.Error("LDAPS 证书验证失败: %v", err)
				client.Warn("请注意: 端口已开放，但 TLS 证书验证失败")
				client.Debug("解决方案: 1.启用调试模式(跳过验证) 2.导入正确证书 3.检查证书名称")
				return nil, fmt.Errorf("LDAPS 证书验证失败: %v", err)
			}
			return nil, fmt.Errorf("LDAPS 连接失败: %v", err)
		}

		// 获取证书信息
		tlsConn, ok := conn.TLSConnectionState()
		if ok && len(tlsConn.PeerCertificates) > 0 {
			cert := tlsConn.PeerCertificates[0]
			client.Info("LDAPS 证书验证通过:")
			client.Debug("  - 证书主题: %s", cert.Subject.CommonName)
			if len(cert.DNSNames) > 0 {
				client.Debug("  - 证书域名: %v", cert.DNSNames)
			}
			client.Debug("  - 颁发者: %s", cert.Issuer.CommonName)
			client.Debug("  - 有效期: %s 至 %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))

			// 检查证书是否即将过期（30天内）
			if time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter) {
				client.Warn("  - 警告: 证书即将过期！剩余 %d 天", int(cert.NotAfter.Sub(time.Now()).Hours()/24))
			}
		} else {
			client.Info("LDAPS 安全连接成功，但未能获取证书详细信息")
		}
	} else {
		// 使用DialURL建立普通连接
		client.Debug("尝试建立 LDAP 标准连接...")
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", address))

		if err != nil {
			return nil, fmt.Errorf("LDAP 服务连接失败: %v", err)
		}

		client.Info("LDAP 标准连接成功")
	}

	return conn, nil
}
