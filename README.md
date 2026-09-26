# dsh-destinywind-tpm

跨平台硬件级凭据存储插件（DSH bundle）。引用值与记录在落盘前用本机最强的密钥保护者封存（AES-256-GCM 信封加密），只在 resolve 时解封：

- **Windows**：TPM（CNG Microsoft Platform Crypto Provider）优先，回退 DPAPI
- **Linux**：TPM 2.0（tpm2-tools）优先，回退会话密钥环（libsecret）
- 两者皆不可用则**拒绝挂载，绝不落明文**

## 安装

声明了 `dsh.bundle.patch`，装完即生效，无需手工编辑任何配置文件：

```text
plugin_manager { action: "install_bundle", target: "<本仓库绝对路径>" }
```

命令行等价形式：

```sh
dsh plugin --profile web add link:<本仓库绝对路径>
```

安装后**重启 `dsh web`** 生效。本补丁会按 id 覆盖默认的 `credentials` 行（置 `disabled: true`）——一个上下文只能提供一个 `credentials` 服务。

## 行为要点

- 密库文件：`$DSH_HOME/.credentials.dpapi.json`（权限 0600，staging + 原子 rename 落盘）
- **没有明文回退层**：全新安装在新值保存之前解析不到任何凭据，这是刻意设计
- 密钥绑定本机本用户：密库文件复制到其他机器/账户无法解密，备份即失效
- 禁用本 bundle 恢复默认提供方；已封存的值保持封存，需为默认提供方重新录入
- 启动时校验：重新解封全部密文，任何解封失败都会报错而非静默降级

## 换装影响：已输入的密钥会怎样

凭据服务在本机只有一个实现槽位：本插件与官方 `@deepseek-ai/dsh-credentials-local`（明文 `.credentials.yaml`）互斥占位，消费方（设置页、各插件）只认标准接口，不关心背后是谁。因此换引擎只影响**存在凭据服务里的值**。

**完全不受影响**：

- 模型连接器的账号登录态（workbuddy / trae 等走各自的登录流程，不经过凭据服务）
- 进程环境变量与 `.env` 文件里的值（见下方解析顺序，这两层在密库之外）

**受影响、需重录一次**：凭据服务里的引用值——包括在设置页输入的模型 API Key（如 DeepSeek 提供器把 Key 存为凭据引用 `DEEPSEEK_API_KEY`，插件配置里只留引用名，真值在凭据服务）。

**解析顺序**（与官方提供方一致，`process` → 密库 → `.env`）：

1. 进程环境变量（启动 dsh 的 shell 或系统用户变量）
2. 本插件密库（官方提供方则为 `.credentials.yaml`）
3. 项目 `.env`（启动目录）→ 用户 `.env`（`$DSH_HOME/.env`）

**两个方向都无迁移，刻意设计**：

- 从官方明文提供方换到本插件：`.credentials.yaml` 里的旧值不会被读取；设置页这些 Key 显示未配置，**重新录入一遍即入封存库**。旧文件原样保留，确认无用后可自行删除。
- 禁用/卸载本插件回到官方：封存值保持封存，官方提供方读不到，同样需重录（密库文件留在原地，装回即恢复）。

**优先级陷阱**：进程环境变量**压过密库**——同名变量存在时解析直接用它，密库值被遮蔽；此时 `set`/`unset` 也会拒绝写入该引用（防误改）。症状「在设置里改了 Key 但不生效」先查启动环境里有没有旧变量，而不是反复重录。

## 测试

`tests/` 是本机集成测试（离线端到端 + 模块解析钩子），依赖本机 `D:\dsh` 安装环境（路径硬编码），不能直接在 CI 运行：

```sh
node --import ./tests/resolve-hook.mjs tests/offline.mjs
```

## 许可

MIT，见 [LICENSE](LICENSE)。
