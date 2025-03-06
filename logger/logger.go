package logger

import (
	"fmt"
	"log"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// 日志级别常量
const (
	LogLevelDebug = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// 日志级别前缀
var logLevelPrefix = map[int]string{
	LogLevelDebug: "[DEBUG] ",
	LogLevelInfo:  "[INFO] ",
	LogLevelWarn:  "[WARN] ",
	LogLevelError: "[ERROR] ",
}

// Logger 结构体用于管理日志功能
type Logger struct {
	debugMode    bool
	updateStatus func(string)
}

// New 创建一个新的Logger实例
func New(debugMode bool, updateStatus func(string)) *Logger {
	logger := &Logger{
		debugMode:    debugMode,
		updateStatus: updateStatus,
	}

	// 设置自定义日志输出
	logWriter := &statusWriter{updateStatus: updateStatus, debugMode: debugMode}
	log.SetOutput(logWriter)

	// 设置日志标志
	if debugMode {
		log.SetFlags(log.Ltime | log.Lmicroseconds | log.Lshortfile)
	} else {
		// 正常模式下使用较为简单的日志格式，但不完全禁用
		log.SetFlags(log.Ltime)
	}

	return logger
}

// Debug 输出调试级别日志
func (l *Logger) Debug(format string, args ...interface{}) {
	l.logMessage(LogLevelDebug, format, args...)
}

// Info 输出信息级别日志
func (l *Logger) Info(format string, args ...interface{}) {
	l.logMessage(LogLevelInfo, format, args...)
}

// Warn 输出警告级别日志
func (l *Logger) Warn(format string, args ...interface{}) {
	l.logMessage(LogLevelWarn, format, args...)
}

// Error 输出错误级别日志
func (l *Logger) Error(format string, args ...interface{}) {
	l.logMessage(LogLevelError, format, args...)
}

// logMessage 统一的日志记录函数
func (l *Logger) logMessage(level int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05.000")

	// 添加日志级别前缀
	prefix := logLevelPrefix[level]
	formattedMsg := fmt.Sprintf("%s %s%s", timestamp, prefix, msg)

	// 简略消息（没有时间戳和详细前缀）
	simplifiedMsg := fmt.Sprintf("%s %s", prefix, msg)

	// 调试模式下 - 显示所有级别的完整信息
	if l.debugMode {
		log.Printf(msg)
		l.updateStatus(formattedMsg)
		return
	}

	// 非调试模式下的处理
	switch level {
	case LogLevelDebug:
		// 调试日志在非调试模式下不显示
		return
	case LogLevelInfo:
		// 信息日志只显示简略信息
		l.updateStatus(simplifiedMsg)
	case LogLevelWarn, LogLevelError:
		// 警告和错误级别显示完整信息，包括时间戳
		log.Printf(msg)
		l.updateStatus(formattedMsg)
	}
}

// 自定义日志写入器，将日志写入状态区
type statusWriter struct {
	updateStatus func(string)
	debugMode    bool
}

func (w *statusWriter) Write(p []byte) (n int, err error) {
	// 移除末尾的换行符
	msg := strings.TrimSpace(string(p))
	timestamp := time.Now().Format("15:04:05.000")

	if w.debugMode {
		// 调试模式下显示详细信息
		formattedMsg := fmt.Sprintf("%s %s%s", timestamp, logLevelPrefix[LogLevelDebug], msg)
		w.updateStatus(formattedMsg)
	} else {
		// 非调试模式下只更新状态区，不做额外处理
		// 具体的日志级别控制已经在logMessage中处理
	}

	return len(p), nil
}

// CreateStatusArea 创建状态显示区域
func CreateStatusArea() (*widget.Entry, *container.Scroll) {
	statusArea := widget.NewMultiLineEntry()
	statusArea.Disable()                    // 设置为只读模式
	statusArea.Wrapping = fyne.TextWrapWord // 启用自动换行

	// 设置初始文本样式
	statusArea.TextStyle = fyne.TextStyle{
		Bold:      false,
		Italic:    false,
		Monospace: true, // 使用等宽字体确保显示一致
	}

	// 状态容器
	statusContainer := container.NewVScroll(statusArea)

	return statusArea, statusContainer
}

// CreateUpdateStatusFunc 创建状态更新函数
func CreateUpdateStatusFunc(statusArea *widget.Entry, statusContainer *container.Scroll) func(string) {
	return func(status string) {
		// 将新状态添加到文本开头而不是末尾
		if statusArea.Text == "" {
			statusArea.SetText(status + "\n")
		} else {
			statusArea.SetText(status + "\n" + statusArea.Text)
		}

		// 确保文本样式保持一致
		statusArea.TextStyle = fyne.TextStyle{
			Bold:      false,
			Italic:    false,
			Monospace: true,
		}

		// 滚动到顶部以显示最新信息
		go func() {
			time.Sleep(50 * time.Millisecond)
			statusArea.CursorRow = 0 // 将光标设置到第一行
			statusArea.Refresh()
			statusContainer.ScrollToTop() // 滚动到顶部
		}()
	}
}
