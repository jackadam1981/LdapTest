package ldap

import "time"

// LDAPConfig 定义LDAP客户端配置
type LDAPConfig struct {
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
	UseTLS     bool
	SkipVerify bool
}
