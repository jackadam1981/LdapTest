// Package ldap 提供LDAP客户端功能
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"LdapTest/logger"

	"github.com/go-ldap/ldap/v3"
)

// SkipTLSVerify 控制是否跳过TLS证书验证
var SkipTLSVerify bool

// GetSkipTLSVerify 获取当前TLS验证状态
func GetSkipTLSVerify() bool {
	return SkipTLSVerify
}

// SetSkipTLSVerify 设置TLS验证状态
func SetSkipTLSVerify(skip bool) {
	SkipTLSVerify = skip
}

// LDAPClient 是LDAP客户端结构体
type LDAPClient struct {
	Host         string
	Port         int
	BindDN       string
	BindPassword string
	Logger       *logger.BaseLogger
	conn         *ldap.Conn
	updateStatus func(string)
	isSSLMode    bool
	debugMode    bool
}

// NewLDAPClient 创建新的LDAP客户端
func NewLDAPClient(host string, port int, bindDN, bindPassword string, logger *logger.BaseLogger, updateFunc func(string), useTLS, debugMode bool) *LDAPClient {
	return &LDAPClient{
		Host:         host,
		Port:         port,
		BindDN:       bindDN,
		BindPassword: bindPassword,
		Logger:       logger,
		updateStatus: updateFunc,
		isSSLMode:    useTLS,
		debugMode:    debugMode,
	}
}

// GetURL 返回LDAP服务器的URL
func (client *LDAPClient) GetURL() string {
	protocol := "ldap"
	if client.isSSLMode {
		protocol = "ldaps"
	}
	return protocol + "://" + client.Host + ":" + fmt.Sprintf("%d", client.Port)
}

// GetTLSConfig 获取TLS配置
func (client *LDAPClient) GetTLSConfig() *tls.Config {
	client.Debug("TLS配置：跳过验证=%v", SkipTLSVerify)
	return &tls.Config{
		InsecureSkipVerify: SkipTLSVerify,
		ServerName:         client.Host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
}

// Connect 连接到LDAP服务器
func (client *LDAPClient) Connect() error {
	client.Info("正在连接到 %s", client.GetURL())
	client.Debug("TLS验证状态：%v", SkipTLSVerify)

	address := fmt.Sprintf("%s:%d", client.Host, client.Port)
	var err error

	if client.isSSLMode {
		tlsConfig := client.GetTLSConfig()
		client.Debug("使用TLS配置：跳过验证=%v", tlsConfig.InsecureSkipVerify)
		client.conn, err = ldap.DialURL("ldaps://"+address, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		client.conn, err = ldap.DialURL("ldap://" + address)
	}

	if err != nil {
		return errors.New("连接LDAP服务器失败: " + err.Error())
	}

	client.conn.SetTimeout(5 * time.Second)
	return nil
}

// Bind 绑定到LDAP服务器
func (client *LDAPClient) Bind(bindDN, bindPassword string) error {
	if client.conn == nil {
		return errors.New("未连接到LDAP服务器")
	}

	return client.conn.Bind(bindDN, bindPassword)
}

// BindWithRetry 带重试的绑定操作
func (client *LDAPClient) BindWithRetry(bindDN, bindPassword string) error {
	const maxRetries = 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := client.ensureConnection(); err != nil {
			lastErr = err
			client.Error("连接失败 (尝试 %d/3): %v", attempt, err)
			continue
		}

		if err := client.conn.Bind(bindDN, bindPassword); err != nil {
			lastErr = err
			client.Error("绑定失败 (尝试 %d/3): %v", attempt, err)

			if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == 200 {
				client.Close()
				continue
			}

			return err
		}

		return nil
	}

	return errors.New("绑定失败，已重试3次: " + lastErr.Error())
}

// ensureConnection 确保连接有效
func (client *LDAPClient) ensureConnection() error {
	if client.conn == nil {
		return client.Connect()
	}

	if !client.IsConnectionValid() {
		client.Close()
		return client.Connect()
	}

	return nil
}

// EnsureConnection 确保LDAP连接有效，如果无效则尝试重新连接
func (client *LDAPClient) EnsureConnection() error {
	if client == nil {
		return errors.New("LDAP客户端对象为空")
	}

	if client.IsConnectionValid() {
		return nil
	}

	client.Warn("检测到连接已关闭，正在重新连接...")
	client.Close()

	if err := client.Connect(); err != nil {
		client.Error("重新连接失败: %v", err)
		return errors.New("重新连接失败: " + err.Error())
	}

	if client.BindDN != "" && client.BindPassword != "" {
		if err := client.Bind(client.BindDN, client.BindPassword); err != nil {
			client.Error("重新绑定失败: %v", err)
			return errors.New("重新绑定失败: " + err.Error())
		}
	}

	client.Info("重新连接成功")
	return nil
}

// IsConnectionValid 检查LDAP连接是否有效
func (client *LDAPClient) IsConnectionValid() bool {
	if client.conn == nil {
		return false
	}

	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		3,
		false,
		"(objectClass=*)",
		[]string{"supportedLDAPVersion"},
		nil,
	)

	_, err := client.conn.Search(searchRequest)
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == 200 {
			return false
		}
		return false
	}

	return true
}

// Close 关闭LDAP连接
func (client *LDAPClient) Close() {
	if client.conn != nil {
		client.conn.Close()
		client.conn = nil
	}
}

// IsPortOpen 检查LDAP端口是否开放
func (client *LDAPClient) IsPortOpen() bool {
	address := net.JoinHostPort(client.Host, fmt.Sprintf("%d", client.Port))
	client.Debug("正在检查端口 %s 是否开放", address)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		client.Warn("端口 %d 未开放: %v", client.Port, err)
		return false
	}
	conn.Close()
	return true
}

// TestLDAPService 测试LDAP服务是否正常
func (client *LDAPClient) TestLDAPService() bool {
	client.Debug("正在测试LDAP服务")
	conn, err := client.GetConnection()
	if err != nil {
		client.Error("LDAP服务连接失败: %v", err)
		return false
	}
	defer conn.Close()

	// 尝试绑定
	err = conn.Bind(client.BindDN, client.BindPassword)
	if err != nil {
		client.Error("LDAP绑定失败: %v", err)
		return false
	}

	client.Info("LDAP服务测试成功")
	return true
}

// GetConnection 获取LDAP连接
func (client *LDAPClient) GetConnection() (*ldap.Conn, error) {
	client.Debug("尝试连接到 %s:%d", client.Host, client.Port)
	client.Debug("TLS验证状态：%v", SkipTLSVerify)

	var l *ldap.Conn
	var err error

	if client.isSSLMode {
		client.Debug("使用TLS连接")
		tlsConfig := client.GetTLSConfig()
		client.Debug("TLS配置详情：跳过验证=%v, 服务器名=%s", tlsConfig.InsecureSkipVerify, tlsConfig.ServerName)
		l, err = ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", client.Host, client.Port), ldap.DialWithTLSConfig(tlsConfig))
	} else {
		client.Debug("使用标准连接")
		l, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", client.Host, client.Port))
	}

	if err != nil {
		client.Error("连接失败：%v", err)
		if strings.Contains(err.Error(), "certificate signed by unknown authority") {
			client.Debug("检测到证书验证错误，当前TLS验证状态：%v", SkipTLSVerify)
			return nil, errors.New("SSL证书验证失败：证书由未知机构签名\n请检查证书是否有效，或考虑跳过TLS验证")
		}
		return nil, errors.New("LDAP连接失败: " + err.Error())
	}

	// 如果提供了凭证，尝试绑定
	if client.BindDN != "" && client.BindPassword != "" {
		client.Debug("尝试使用提供的凭证绑定")
		if err := l.Bind(client.BindDN, client.BindPassword); err != nil {
			client.Error("绑定失败：%v", err)
			l.Close()
			return nil, errors.New("LDAP绑定失败: " + err.Error())
		}
		client.Debug("绑定成功")
	}

	return l, nil
}

// Shutdown 关闭LDAP连接并释放资源
func (client *LDAPClient) Shutdown() {
	client.Close()
}

// TestServiceConnection 测试LDAP服务连接（不包括绑定验证）
func (client *LDAPClient) TestServiceConnection() (*ldap.Conn, error) {
	client.Debug("正在测试LDAP服务连接")
	conn, err := client.GetConnection()
	if err != nil {
		client.Error("LDAP服务连接失败: %v", err)
		return nil, err
	}
	client.Info("LDAP服务连接成功")
	return conn, nil
}

// Debug 记录调试级别日志
func (client *LDAPClient) Debug(format string, args ...interface{}) {
	client.Logger.Debug(format, args...)
}

// Info 记录信息级别日志
func (client *LDAPClient) Info(format string, args ...interface{}) {
	client.Logger.Info(format, args...)
}

// Warn 记录警告级别日志
func (client *LDAPClient) Warn(format string, args ...interface{}) {
	client.Logger.Warn(format, args...)
}

// Error 记录错误级别日志
func (client *LDAPClient) Error(format string, args ...interface{}) {
	client.Logger.Error(format, args...)
}

// SetDebugMode 设置调试模式
func (client *LDAPClient) SetDebugMode(debug bool) {
	client.debugMode = debug
	client.Logger.SetDebugMode(debug)
}
