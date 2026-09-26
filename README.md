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

## 测试

`tests/` 是本机集成测试（离线端到端 + 模块解析钩子），依赖本机 `D:\dsh` 安装环境（路径硬编码），不能直接在 CI 运行：

```sh
node --import ./tests/resolve-hook.mjs tests/offline.mjs
```

## 许可

MIT，见 [LICENSE](LICENSE)。
