// Package ui 提供用户界面相关组件和主题
package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// MyTheme 是应用程序的自定义主题
type MyTheme struct {
	fyne.Theme
}

// NewMyTheme 创建一个新的自定义主题实例，直接返回主题对象
func NewMyTheme() fyne.Theme {
	return &MyTheme{Theme: theme.DefaultTheme()}
}

// Color 返回指定主题颜色
func (m MyTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// 修改禁用状态文字颜色为纯黑色
	if name == theme.ColorNameDisabled {
		return &color.NRGBA{R: 0, G: 0, B: 0, A: 255} // RGBA(0,0,0,255)
	}
	// 其他颜色使用默认主题设置
	return m.Theme.Color(name, variant)
}

// Font 返回指定文本样式的字体
func (m MyTheme) Font(style fyne.TextStyle) fyne.Resource {
	return m.Theme.Font(style)
}

// Icon 返回指定名称的图标
func (m MyTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return m.Theme.Icon(name)
}

// Size 返回指定主题尺寸
func (m MyTheme) Size(name fyne.ThemeSizeName) float32 {
	return m.Theme.Size(name)
}
