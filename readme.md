用go做一个ldap连接测试软件。
经常做ldap对接，有部分系统的测试功能不完整，甚至有的都没有。
那就做一个测试ldap服务器的简单工具吧。

# Go 环境配置

## 安装后无法识别 Go 命令？

1. 确保已将 Go 的安装路径添加到系统环境变量中：
   - Windows: 将 `C:\Go\bin` 添加到 `PATH`
   - macOS/Linux: 将 `/usr/local/go/bin` 添加到 `PATH`

2. 验证安装：
   ```bash
   go version
   ```

3. 如果仍然无法识别，请检查：
   - 是否正确安装了 Go
   - 是否重新启动了终端
   - 环境变量是否设置正确
