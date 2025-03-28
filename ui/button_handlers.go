package ui

import (
	"fyne.io/fyne/v2/widget"
)

// CreateButtonHandlers 创建所有按钮的回调函数
func CreateButtonHandlers(ops *LDAPOperations, entries *UIEntries) map[string]func() {
	return map[string]func(){
		"ping": func() {
			ops.HandlePing(entries.DomainEntry.Text)
		},
		"portTest": func() {
			ops.HandlePortTest(entries.DomainEntry.Text, entries.PortEntry, ops.isSSLMode)
		},
		"adminTest": func() {
			ops.HandleAdminTest(entries.DomainEntry.Text, entries.AdminEntry.Text, entries.PasswordEntry.Text, entries.PortEntry, ops.isSSLMode)
		},
		"createLdap": func() {
			ops.HandleCreateLdap(entries.DomainEntry.Text, entries.AdminEntry.Text, entries.PasswordEntry.Text, entries.LdapDNEntry.Text, entries.LdapPasswordEntry.Text, entries.LdapGroupEntry.Text, entries.SearchDNEntry.Text, entries.PortEntry, ops.isSSLMode)
		},
		"groupCheck": func() {
			ops.HandleGroupCheck(entries.DomainEntry.Text, entries.AdminEntry.Text, entries.PasswordEntry.Text, entries.LdapGroupEntry.Text, entries.SearchDNEntry.Text, entries.PortEntry, ops.isSSLMode)
		},
		"adminTestUser": func() {
			ops.HandleAdminTestUser(entries.DomainEntry.Text, entries.AdminEntry.Text, entries.PasswordEntry.Text, entries.TestUserEntry.Text, entries.TestPasswordEntry.Text, entries.SearchDNEntry.Text, entries.PortEntry, ops.isSSLMode)
		},
		"ldapTestUser": func() {
			ops.HandleLdapTestUser(entries.DomainEntry.Text, entries.LdapDNEntry.Text, entries.LdapPasswordEntry.Text, entries.TestUserEntry.Text, entries.TestPasswordEntry.Text, entries.SearchDNEntry.Text, entries.PortEntry, ops.isSSLMode)
		},
	}
}

// UIEntries 存储所有UI输入框的引用
type UIEntries struct {
	DomainEntry       *CustomDomainEntry
	AdminEntry        *widget.Entry
	PasswordEntry     *widget.Entry
	LdapPasswordEntry *widget.Entry
	LdapDNEntry       *widget.Entry
	LdapGroupEntry    *widget.SelectEntry
	SearchDNEntry     *widget.Entry
	TestUserEntry     *widget.Entry
	TestPasswordEntry *widget.Entry
	PortEntry         *CustomPortEntry
	FilterSelect      *widget.Select
}
