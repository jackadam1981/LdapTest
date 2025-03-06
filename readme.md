用go做一个ldap连接测试软件。
经常做ldap对接，有部分系统的测试功能不完整，甚至有的都没有。
那就做一个测试ldap服务器的简单工具吧。

### **权限矩阵说明**

### LDAP集成账号权限矩阵

| 功能模块          | 操作描述           | 权限类型                    | 作用对象/属性                 | 继承范围 | 安全建议            |
| ----------------- | ------------------ | --------------------------- | ----------------------------- | -------- | ------------------- |
| 基础连接          |                    |                             |                               |          |                     |
| 1. LDAP绑定       | 执行身份验证操作   | GenericExecute              | 目标用户对象                  | 不继承   | 仅限必要用户容器    |
| 用户属性读取      |                    |                             |                               |          |                     |
| 2. 基本信息查询   | 读取用户标识属性   | ReadProperty                | cn, sAMAccountName, mail      | 用户对象 | 禁止读取objectSid   |
| 3. 账户状态检查   | 检查账户有效性     | ReadProperty                | userAccountControl            | 用户对象 | 结合lockoutTime使用 |
| 4. 密码策略验证   | 读取密码相关属性   | ReadProperty                | pwdLastSet, badPwdCount       | 用户对象 | 禁止写入            |
| 组织架构访问      |                    |                             |                               |          |                     |
| 5. OU结构浏览     | 查看组织单位层级   | ListChildren + ReadProperty | distinguishedName             | OU容器   | 限制到特定顶级OU    |
| 6. 用户部门识别   | 获取用户所属OU     | ReadProperty                | distinguishedName             | 用户对象 | 仅允许读取OU路径    |
| 组关系管理        |                    |                             |                               |          |                     |
| 7. 直接组成员查询 | 获取用户直属组     | ReadProperty                | memberOf                      | 用户对象 | 禁止读取admin组     |
| 8. 嵌套组解析     | 递归查询组嵌套关系 | ReadProperty + ListChildren | member                        | 组对象   | 限制递归深度        |
| 9. 组属性读取     | 读取组基本信息     | ReadProperty                | description, groupType        | 组对象   | 禁止读取敏感组属性  |
| 审计与监控        |                    |                             |                               |          |                     |
| 10. 登录日志      | 读取最后登录时间   | ReadProperty                | lastLogon, lastLogonTimestamp | 用户对象 | 单独审计账号        |
| 11. 密码修改审计  | 监控密码修改操作   | ReadProperty                | pwdLastSet                    | 用户对象 | 只读权限            |

---

### 典型场景配置示例

#### HR系统集成

权限：1,2,5,6,7
作用域：OU=Employees,DC=corp,DC=com
禁止：lastLogon等日志属性

#### SSO身份提供者（单点登录）

权限：1,2,3,7,8
作用域：CN=Users,DC=corp,DC=com
特殊要求：启用LDAPS+证书验证

#### IT服务台系统

权限：1,2,3,4,7 + 密码重置权限
作用域：OU=Helpdesk,DC=corp,DC=com
注意：密码重置需额外User-Force-Change-Password权限
