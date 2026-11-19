# TraceQuarry Windows 免安装版 / Portable for Windows

64 位 Windows 10/11 可直接运行，**不需要安装 Python**、Docker 或任何依赖。

## 使用方法

1. 把整个 ZIP **完整解压**到任意文件夹（不要在压缩包里直接双击运行）。
2. 双击 `TraceQuarry.exe`。
3. 会出现一个控制台窗口，浏览器自动打开 `http://127.0.0.1:8765/`。
4. 用完后关闭控制台窗口（或按 `Ctrl+C`）即可停止。

首次运行时 Windows SmartScreen 可能提示"未知发布者"（启动器没有代码签名），
点击"更多信息 → 仍要运行"。如果 Windows 防火墙询问，可以直接拒绝：
程序只监听本机回环地址 `127.0.0.1`，不需要任何网络访问。

## 目录说明

| 路径 | 说明 |
| --- | --- |
| `TraceQuarry.exe` | 启动本地 Web 界面 |
| `tracequarry-cli.exe` | 命令行解析器，例如 `tracequarry-cli.exe --input x.tar.gz --out out` |
| `data\` | 首次运行自动创建：上传的证据、解析结果、案件库 |
| `evidence\` | 放在这里（或你的用户目录下）的证据可在界面中按路径加载 |
| `app\` | TraceQuarry 源码、规则 (`rules\*.yml`) 与前端资源 |
| `runtime\` | 内置的官方 CPython 3.12 运行时 |

如果程序所在文件夹不可写（例如 `C:\Program Files`），数据会自动改存到
`%LOCALAPPDATA%\TraceQuarry\data`。也可以用环境变量 `TRACEQUARRY_DATA_DIR` 指定。

## 启动参数

`TraceQuarry.exe` 接受 `tracequarry-web` 的全部参数，另加 `--no-browser`：

```bat
TraceQuarry.exe --port 9000 --no-browser
TraceQuarry.exe --input-root D:\cases --max-upload-gib 16
TraceQuarry.exe --help
```

- 默认端口 8765；被占用时自动顺延到下一个空闲端口。
- 已经有一个实例在运行时，再次双击只会打开浏览器，不会重复启动。
- 默认允许按路径加载的根目录是 `evidence\` 和你的用户目录；
  其他位置请用 `--input-root` 指定（可重复）。

## 与源码安装的区别

- 运行时完全隔离：不读取系统已安装的 Python、注册表、`PYTHONPATH`。
- 内置 `tzdata`：Windows 没有系统 IANA 时区库，没有它时
  `Asia/Shanghai` 这类时区名无法解析。
- 标准库与应用均已预编译为字节码，启动更快，文件数量更少。

## 安全边界

与上游一致：TraceQuarry 是单机、仅回环访问的工具，没有登录认证，
**不要**把端口暴露到局域网或互联网。原始证据请另行保存备份。

---

**English:** extract the whole ZIP, double-click `TraceQuarry.exe`, and the
loopback-only GUI opens in your browser. No Python installation is required.
Close the console window to stop. Data is stored in `data\` next to the
program. Licensed under Apache-2.0; see `licenses\`.
