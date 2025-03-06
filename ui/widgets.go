package ui

import (
	"fmt"
	"strconv"

	"fyne.io/fyne/v2/widget"
)

// CustomDomainEntry 是一个自定义的域名输入框
type CustomDomainEntry struct {
	widget.Entry
	onFocusLost func() // 焦点丢失时的回调函数
}

// NewCustomDomainEntry 创建一个新的自定义域名输入框
func NewCustomDomainEntry(onFocusLost func()) *CustomDomainEntry {
	entry := &CustomDomainEntry{onFocusLost: onFocusLost}
	entry.ExtendBaseWidget(entry)
	return entry
}

// FocusLost 当输入框失去焦点时调用
func (e *CustomDomainEntry) FocusLost() {
	e.Entry.FocusLost()
	if e.onFocusLost != nil {
		e.onFocusLost()
	}
}

// CustomPortEntry 是一个自定义的端口输入框
type CustomPortEntry struct {
	widget.Entry
}

// NewCustomPortEntry 创建一个新的自定义端口输入框
func NewCustomPortEntry() *CustomPortEntry {
	entry := &CustomPortEntry{}
	entry.ExtendBaseWidget(entry)
	entry.SetPlaceHolder("请输入LDAP端口 (1-65535)")
	return entry
}

// FocusLost 当输入框失去焦点时调用
func (e *CustomPortEntry) FocusLost() {
	e.Entry.FocusLost()

	// 验证端口号
	if e.Text != "" {
		if port, err := strconv.Atoi(e.Text); err != nil || port < 1 || port > 65535 {
			e.SetText("389") // 设置为默认端口
		}
	}
}

// FocusGained 当输入框获得焦点时调用
func (e *CustomPortEntry) FocusGained() {
	e.Entry.FocusGained()

	// 如果输入框为空，则填充默认值389
	if e.Text == "" {
		e.SetText("389")
		// 全选文本，便于用户直接替换
		currentText := e.Text
		e.SetText("")
		e.SetText(currentText)
	}

	// 如果是默认值，则选择文本以便用户直接替换
	if e.Text == "389" || e.Text == "636" {
		// 全选文本，便于用户直接替换
		currentText := e.Text
		e.SetText("")
		e.SetText(currentText)
	}
}

// SetDefaultPort 根据SSL状态设置默认端口
func (e *CustomPortEntry) SetDefaultPort(ssl bool) {
	if ssl {
		e.SetText("636") // SSL端口
	} else {
		e.SetText("389") // 标准端口
	}
}

// GetPort 获取端口号
func (e *CustomPortEntry) GetPort() (int, error) {
	if e.Text == "" {
		return 0, fmt.Errorf("端口号不能为空")
	}

	port, err := strconv.Atoi(e.Text)
	if err != nil {
		return 0, fmt.Errorf("无效的端口号: %v", err)
	}

	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("端口号必须在1-65535之间")
	}

	return port, nil
}
