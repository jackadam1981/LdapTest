package logger

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// LogLevel 定义日志级别
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// LogEntry 定义结构化日志条目
type LogEntry struct {
	Timestamp string
	Level     string
	Message   string
	Fields    map[string]interface{}
}

// Logger 定义日志记录器结构
type Logger struct {
	debugMode       bool
	statusArea      *widget.TextGrid
	statusContainer *fyne.Container
	updateFunc      func(string)
}

// New 创建新的日志记录器
func New(debugMode bool, updateFunc func(string)) *Logger {
	return &Logger{
		debugMode:  debugMode,
		updateFunc: updateFunc,
	}
}

// log 统一的日志记录方法
func (b *BaseLogger) log(level LogLevel, format string, args ...interface{}) {
	// 创建日志条目
	entry := LogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Level:     level.String(),
		Message:   fmt.Sprintf(format, args...),
		Fields:    make(map[string]interface{}),
	}

	// 构建日志消息
	message := fmt.Sprintf("[%s] %s: %s", entry.Timestamp, entry.Level, entry.Message)

	// 如果有额外字段，添加到消息中
	if len(entry.Fields) > 0 {
		message += " | "
		for k, v := range entry.Fields {
			message += fmt.Sprintf("%s=%v ", k, v)
		}
	}

	// 更新状态区域
	b.updateFunc(message)
}

// Debug 记录调试级别日志
func (b *BaseLogger) Debug(format string, args ...interface{}) {
	if b.logger.debugMode {
		b.log(DEBUG, format, args...)
	}
}

// Info 记录信息级别日志
func (b *BaseLogger) Info(format string, args ...interface{}) {
	b.log(INFO, format, args...)
}

// Warn 记录警告级别日志
func (b *BaseLogger) Warn(format string, args ...interface{}) {
	b.log(WARN, format, args...)
}

// Error 记录错误级别日志
func (b *BaseLogger) Error(format string, args ...interface{}) {
	b.log(ERROR, format, args...)
}

// String 返回日志级别的字符串表示
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// WithFields 添加结构化字段到日志条目
func (b *BaseLogger) WithFields(fields map[string]interface{}) *BaseLogger {
	// 创建一个新的BaseLogger，继承原有功能但添加字段
	return &BaseLogger{
		logger: b.logger,
		updateFunc: func(message string) {
			entry := LogEntry{
				Timestamp: time.Now().Format("2006-01-02 15:04:05"),
				Level:     INFO.String(),
				Message:   message,
				Fields:    fields,
			}
			formattedMessage := fmt.Sprintf("[%s] %s: %s", entry.Timestamp, entry.Level, entry.Message)
			if len(entry.Fields) > 0 {
				formattedMessage += " | "
				for k, v := range entry.Fields {
					formattedMessage += fmt.Sprintf("%s=%v ", k, v)
				}
			}
			b.updateFunc(formattedMessage)
		},
	}
}

// SetDebugMode 设置调试模式
func (b *BaseLogger) SetDebugMode(debug bool) {
	if b.logger != nil {
		b.logger.debugMode = debug
	}
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

// SetDebugMode 设置调试模式
func (l *Logger) SetDebugMode(debug bool) {
	l.debugMode = debug
}

// Loggable 定义可记录日志的接口
type Loggable interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// BaseLogger 提供基础的日志功能
type BaseLogger struct {
	logger     *Logger
	updateFunc func(string)
}

// NewBaseLogger 创建新的基础日志记录器
func (l *Logger) NewBaseLogger(updateFunc func(string)) *BaseLogger {
	return &BaseLogger{
		logger:     l,
		updateFunc: updateFunc,
	}
}
