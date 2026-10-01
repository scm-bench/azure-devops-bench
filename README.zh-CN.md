<!--
  Banner 放在 scm-bench/.github 的 brand/ 下，组织 profile 和上传用的头像也都
  取自那里，全组织只有一份。这里用绝对地址有两个原因：相对路径跨不了仓库；而且
  README 会被打进每个 release 压缩包，那里没有仓库树可供解析。
-->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-dark-1760x440.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-light-1760x440.png">
    <img src="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-light-1760x440.png" alt="azure-devops-bench — audit Azure DevOps against the CIS supply chain benchmark" width="880">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/scm-bench/azure-devops-bench/actions/workflows/ci.yml"><img src="https://github.com/scm-bench/azure-devops-bench/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/scm-bench/azure-devops-bench/releases"><img src="https://img.shields.io/github/v/release/scm-bench/azure-devops-bench?include_prereleases&sort=semver" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/scm-bench/azure-devops-bench"><img src="https://goreportcard.com/badge/github.com/scm-bench/azure-devops-bench" alt="Go report card"></a>
  <a href="https://pkg.go.dev/github.com/scm-bench/azure-devops-bench"><img src="https://pkg.go.dev/badge/github.com/scm-bench/azure-devops-bench.svg" alt="Go reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0"></a>
</p>

依据 [CIS 软件供应链安全指南](https://www.cisecurity.org/benchmark/software-supply-chain-security)
的 **Source Code** 章节审计 **Azure DevOps** —— Azure Repos 以及围绕它的项目与组织设置。

azure-devops-bench 以**只读**方式抓取一个 Azure DevOps Services 组织（或一个
Azure DevOps Server 2022+ 集合）的快照，用 Rego 编写的策略进行判定，然后告诉你哪里配置有问题
——并给出修复所需的确切设置路径，以及一次性修好所有仓库的项目级设置。

**v0.1** 映射了 24 条规则：21 条自动判定；另有 3 条以「明确记录的人工检查」形式保留，
使映射关系完整，而不是悄悄地只做一半。

本仓库是 [scm-bench](https://github.com/scm-bench/scm-bench) 家族中负责 Azure DevOps 的那一个。
家族里每个工具审计一个平台，并以同样的形态输出报告。它实现了家族的
[bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
与 [SCM 快照 schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md)。

[English](README.md) · [贡献指南](CONTRIBUTING.md) · [安全策略](SECURITY.md) · [遵循的规范](#遵循的规范)

---

## 唯一需要先了解的设计决定

**无法判定的规则输出 `MANUAL`，绝不输出 `PASS` 或 `FAIL`。**

如果 token 读不到权限、部署形态根本没有对应的 API（Azure DevOps Server 没有用户授权 API）、
Azure DevOps 返回的是登录页而不是数据——工具会如实说明，并把该规则排除在评分之外。
分数不会因为「没能问出口的问题」而虚高，也不会因此被扣分。

Azure DevOps 还多提出一个要求。审计需要的很多东西——哪些策略作用于某个分支、谁继承了某项
权限、某个 Entra 组里有谁——文档要么语焉不详，要么根本没写。所以凡是必须推断的地方，
工具都按「出错也安全」来设计：

- **两个互相矛盾的回答让设置变成未知。** 服务器声称作用于某分支的策略，会与项目里的全部
  策略交叉核对；任何一个方向对不上，该仓库上基于策略的规则都会变成 `MANUAL`，而不是
  相信其中任何一方。
- **没能完整读取的集合只是下界。** Entra 组只在成员登录过之后才列出他们，所以由它得出的
  人数可以证明 `FAIL`（「至少这些人能 force push」），却永远不能证明 `PASS`。
- **空的回答不等于宽松的回答。** 每个项目默认都有权限条目；一份什么都没有的权限列表会被
  视为不可读，而不是「谁都没有任何权限」。

这些推断，以及对照真实组织逐条核实它们的只读探针，都列在 [`hack/recon`](hack/recon/README.md) 里。

---

## 安装

**二进制** —— 从 [releases](https://github.com/scm-bench/azure-devops-bench/releases) 下载：

```bash
# 压缩包名里带版本号，所以先取最新的 tag。
VERSION=$(curl -fsSL https://api.github.com/repos/scm-bench/azure-devops-bench/releases/latest |
  sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')

curl -fsSL "https://github.com/scm-bench/azure-devops-bench/releases/download/v${VERSION}/azure-devops-bench_${VERSION}_linux_amd64.tar.gz" | tar xz
./azure-devops-bench version
```

**Docker：**

```bash
docker run --rm -e AZURE_DEVOPS_TOKEN ghcr.io/scm-bench/azure-devops-bench:latest \
  scan --url https://dev.azure.com/fabrikam
```

**从源码构建**（Go 1.26+；构建会固定到一个已打补丁的 toolchain 并自动获取）：

```bash
go install github.com/scm-bench/azure-devops-bench/cmd/azure-devops-bench@latest
```

### 校验下载的产物

`checksums.txt` 与容器镜像用 [cosign](https://docs.sigstore.dev/) 做了 keyless 签名——
签名身份就是本仓库的 release workflow，因此不存在需要信任、也不会泄露的密钥。每个压缩包的
摘要都在 `checksums.txt` 里，所以一个签名就覆盖了整次发布；压缩包另外带有 SLSA build
provenance 证明。每次发布的 release notes 里都附上了填好身份参数的 `cosign verify-blob` 与
`gh attestation verify` 命令——那几个身份参数才是关键：不带它们，校验只能确认「有人」签过这个文件。

---

## 快速开始

```bash
export AZURE_DEVOPS_URL=https://dev.azure.com/fabrikam
export AZURE_DEVOPS_TOKEN=<个人访问令牌（PAT），或 Entra 访问令牌>

# 全量扫描
azure-devops-bench scan

# 只扫某个项目 / 某个仓库
azure-devops-bench scan --project Fabrikam-Fiber
azure-devops-bench scan --repository Fabrikam-Fiber/payments-api

# 机器可读输出
azure-devops-bench scan -o json  --output-file report.json
azure-devops-bench scan -o sarif --output-file report.sarif
azure-devops-bench scan -o junit --output-file report.xml
```

`--url` 接受访问 Azure DevOps 的三种形式：

| URL | 部署形态 |
|---|---|
| `https://dev.azure.com/{organization}` | Azure DevOps Services |
| `https://{organization}.visualstudio.com` | Azure DevOps Services 的旧域名（核心 API 仍走这个域名） |
| `https://{server}/{collection}`（或 `…/tfs/{collection}`） | Azure DevOps Server 2022 及更高版本 |

指向组织*内部*的 URL——比如从浏览器里粘过来的项目页面——会被拒绝，并提示本意应该用的
`--project`，而不是悄悄扫描整个组织。不存在（或 token 看不到）的 `--project`、`--repository`
是错误，退出码 `2`，而不是一份空报告。

手边没有组织？二进制里内置了样例，一个参数就能看到第一份报告：

```bash
azure-devops-bench scan --demo
```

在终端里什么都不配置直接运行 `azure-devops-bench scan`，它会交互式地给出同样的选择：现在输入
URL 和 token，或者先看样例。如果你输入了，scan 会**询问**（而不是自作主张）是否在它们被验证
可用之后保存下来。保存位置是用户配置目录下的 `instance.yaml`（Linux 上是
`~/.config/azure-devops-bench/`；`AZURE_DEVOPS_BENCH_CONFIG_DIR` 可改写位置），权限 `0600`——
token 是一份活的凭据。手敲的 `--url` 或导出的 `AZURE_DEVOPS_URL` 永远优先于这个文件，
并且每次用到它的扫描都会在 stderr 上说明。

仓库是并发抓取的，各项目并行、共用同一个上限：`scan.concurrency`（默认 **4**，是
bitbucket-bench 的一半），因为 Azure DevOps Services 按身份在一个滑动的五分钟窗口内限流，
触发限流的扫描睡掉的时间比它省下的还多。每个响应上的 `Retry-After` 都会被遵守，包括
Azure DevOps 在开始延迟请求之前就附在 `200` 上发来的那种。

### 看着它扫

默认情况下，一次扫描显示一行原地刷新的进度，然后是报告。`--verbose` 则按仓库分组记录每个
请求；无论是否 verbose，每次扫描都以一行「token 被用来做了什么」的账目结尾（节选）：

```
[INFO] listing projects
[INFO]   GET  /projects?stateFilter=wellFormed                     200   41ms
[INFO] reading Project Collection Administrators
[INFO]   GET  identity:/identities?filterValue=Project Collection Administrators&searchFilter=General 200   88ms
[INFO]   GET  /accesscontrollists/2e9eb7ed…?recurse=false&token=repoV2(0) 200   63ms
[INFO]   GET  /{project}/policy/configurations                     200   57ms
[INFO] listing repositories in Fabrikam-Fiber
[INFO]   GET  /{project}/git/repositories?includeHidden=true       200   38ms

[INFO]   Fabrikam-Fiber/payments-api
[INFO]     GET  /{project}/git/repositories/278d5cd2…/refs?filter=heads/ 200   35ms
[INFO]     GET  /{project}/git/policy/configurations?refName=refs/heads/main&repositoryId=278d5cd2-584d-4b63-824a-2ba458937249 200   49ms
[INFO]     GET  /{project}/git/repositories/278d5cd2…/stats/branches 200   44ms
[INFO] ✓ 61 requests · 61 GET · 0 writes · read-only
```

**最后一行才是重点。** 它统计的是实际发出的请求方法，而不是「全都是 `GET`」这句承诺；
一旦有非读请求，会显示为 `✗ … NOT READ-ONLY`，而不是被并进总数里。

`scan.progress` 决定显示多少：`compact`（默认）、`full`（`--verbose` 隐含）或 `off`。
输出被重定向或在 CI 里时，`full` 会自动退回 `off`；结尾那行照样打印，因为「token 被用来做了
什么」的账目在 CI 日志里同样有价值。`scan.maxDuration` 会放弃运行过久的扫描（退出码 `2`）；
`scan.timeout` 限制单个请求（默认 30s）。

### token 需要什么权限

azure-devops-bench **只发 `GET` 请求**——由测试强制保证，并由上面那行结尾账目在每次运行时
清点。它能*读到*什么，取决于凭据：

| Scope | 能读到 | 缺少时 |
|---|---|---|
| `vso.project` | 列出项目；扫描开始前的凭据检查 | 扫描无法开始（退出码 `2`） |
| `vso.code` | 仓库、分支、文件和分支策略：CIS-1.1.2–1.1.4、1.1.8、1.1.9、1.1.11–1.1.13、1.2.1，以及 1.1.15–1.1.17 的 `FAIL` 一侧 | 无法列出任何仓库（退出码 `2`） |
| `vso.security_manage` | Git 权限：谁能绕过策略、force push、删除分支或仓库、管理或创建仓库——CIS-1.1.5、1.1.14、1.1.15–1.1.17、1.2.2、1.2.3、1.3.7、1.3.8 | 这些规则输出 `MANUAL`；1.1.15–1.1.17 与 1.3.8 仍可判为失败 |
| `vso.identity` | 解析权限持有者是谁；Server 上的组展开 | 权限集合不完整：只能判失败，不能判通过 |
| `vso.graph` | Services 上的组展开，包括 Project Collection Administrators（CIS-1.3.3） | 集合只是下界 |
| `vso.memberentitlementmanagement` | 用户及其最后访问时间（CIS-1.3.1，Services） | CIS-1.3.1 输出 `MANUAL` |
| `vso.advsec` | Advanced Security 启用状态（CIS-1.5.1，Services） | CIS-1.5.1 输出 `MANUAL` |

**最小集：** `vso.project vso.code` —— 覆盖基于策略的规则，但读不到任何关于「人」的信息。
**推荐：** 再加上 `vso.graph vso.identity vso.security_manage vso.memberentitlementmanagement`
（如果购买了 Advanced Security，再加 `vso.advsec`）。

**请注意 `vso.security_manage` 具有写能力。** Azure DevOps 的安全 API 没有只读 scope：能让
token 读取访问控制列表的那个 scope，同样能让它修改。工具本身只发 `GET`，但 token 的能力超出了
工具所需，请据此对待它：PAT 的权限永远不会超过其所有者，所以请从一个在任何地方都不持有
*Manage permissions* 的账号签发它，缩短有效期，并作为机密保存。如果无法接受这个取舍，就不要
勾选这个 scope——权限类规则会输出 `MANUAL`，扫描的其余部分不受影响。

**请使用组织级（organization-scoped）PAT。** 全局 PAT 将于 **2026 年 12 月 1 日**停止工作；
限定到被扫描组织的 PAT 不受影响。

**企业场景下可以完全不用 PAT：** 用一个 Microsoft Entra 服务主体（或托管标识），以
**Basic** 访问级别加入组织（Stakeholder 读不了 Repos），并加入每个项目的 **Readers** 组，
不加入任何管理员组。Entra token 不受 scope 约束——上限就是该身份自身的权限，而这里它只有
只读权限。把它的 token 当作 token 传入即可；任何形似 JWT 的值都会作为 bearer token 发送：

```bash
export AZURE_DEVOPS_TOKEN=$(az account get-access-token \
  --resource 499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv)
azure-devops-bench scan --url https://dev.azure.com/fabrikam
```

只属于 Readers 的身份能否读到扫描需要的每一份权限列表，正是 [`hack/recon`](hack/recon/README.md)
要核实的事项之一（它的第 3 轮）；读不到的部分输出 `MANUAL`，扫描警告会点明缺了什么。

被 Azure DevOps **拒绝**的凭据会在扫描开始前被检出，以退出码 `2` 结束并说明如何处理：
对 `GET _apis/projects?$top=1` 返回 `203` 登录页、`401`、重定向或非 JSON 回答，含义都一样。
如果把被拒绝的凭据当作缺少权限来处理，一个敲错的 token 就会变成一份全是 `MANUAL` 的完整报告
——看上去像审计结果，而不是笔误。每个请求都带有 `X-TFS-FedAuthRedirect: Suppress`，
并且从不跟随任何重定向。

Azure DevOps Server 使用 PAT。嵌在 URL 里的凭据会在 URL 进入快照或报告之前被剥离，且从不使用。

### 传输

token 能读到它看得见的每一个仓库，所以不会以明文上线路：`http://` URL 会在第一个请求之前被
拒绝，除非主机是 loopback，或者 `scan.allowPlaintext` 声明网络可信。

对于使用内部证书颁发机构的 Azure DevOps Server，把它的证书交给 `scan.caFile`——一个
**追加**到系统根证书（而不是替换它们）的 PEM 证书包，并在启动时校验，所以坏文件是配置错误，
而不是扫描到一半才失败。`scan.insecure` 完全跳过校验，几乎从来都不是正确答案；两者互斥。
代理取自常见的 `HTTPS_PROXY`/`NO_PROXY` 环境变量。

这些都特意放在配置里而不是命令行参数里：削弱传输安全应当是写进文件、有人能审阅的决定。
每一项都会在报告的扫描警告以及以此方式抓取的快照里留下一行记录。

---

## Services 与 Server

两者都有的数据，扫描以同样方式读取；某一方没有的，扫描会明说：

| 扫描读取的内容 | Services | Server 2022+ | 缺失时 |
|---|---|---|---|
| 项目、仓库、分支、文件、分支策略 | 有 | 有 | — |
| Git 权限与身份 | 有 | 有 | — |
| 组展开 | Graph memberships | IMS（`queryMembership=ExpandedDown`） | — |
| 用户最后访问时间 | user entitlements | 没有 API | CIS-1.3.1 输出 `MANUAL`，并点明是 Server |
| GitHub Advanced Security | 有 | 不提供 | CIS-1.5.1 输出 `MANUAL`，并点明是 Server |
| 目录组 | Entra 组：成员登录后才可知 | Active Directory 组：已同步的成员 | 两种情况都只是下界 |

Server 2022 使用 REST `api-version` 7.0，2022.1 及更高版本使用 7.1；扫描先请求 7.1，
必要时自动降到 7.0。更早的 Server 缺少本工具依赖的 API，会以退出码 `2` 拒绝。

---

## 覆盖范围

21 条规则自动判定：

| CIS | 规则 | 严重度 | 判定依据 |
|---|---|---|---|
| 1.1.2 | 变更可追溯到工作项 | LOW | 默认分支上必需的「Check for linked work items」策略 |
| 1.1.3 | 两个独立批准 | HIGH | 必需的最少审阅者策略；允许请求者批准自己的变更时减一 |
| 1.1.4 | 新推送会重置批准 | MEDIUM | 该策略上的「Reset all approval votes」或「Reset all code reviewer votes」 |
| 1.1.5 | 审阅不能被随意绕过 | MEDIUM | 谁持有「Bypass policies when completing pull requests」，组已展开 |
| 1.1.8 | 废弃分支被清理 | LOW | 分支末端提交日期与 `staleBranchDays` 比较 |
| 1.1.9 | 合并前检查必须通过 | HIGH | 必需的、没有路径过滤的构建验证或状态检查策略 |
| 1.1.11 | 合并前评论已解决 | LOW | 必需的「Check for comment resolution」策略 |
| 1.1.12 | 提交签名经过验证 | MEDIUM | `signatureStatusChecks` 中列出的必需状态检查 |
| 1.1.13 | 线性历史 | LOW | 「Limit merge types」所允许的合并类型 |
| 1.1.14 | 保护对管理员同样生效 | MEDIUM | 持有任一绕过权限的管理员（Manage permissions、Project Collection Administrators） |
| 1.1.15 | 不能直接推送到默认分支 | HIGH | 必需的分支策略，以及谁持有「Bypass policies when pushing」 |
| 1.1.16 | 禁止 force push | HIGH | 谁持有 Force push——在必需策略下，还需同时持有推送绕过权限 |
| 1.1.17 | 禁止删除分支 | MEDIUM | 必需的分支策略，以及谁同时持有 Force push 与推送绕过权限 |
| 1.2.1 | 发布了安全策略 | LOW | 默认分支上的 `SECURITY.md`（或配置的路径） |
| 1.2.2 | 仓库创建受限 | MEDIUM | 每个项目中，谁持有 Create repository 却不管理该项目 |
| 1.2.3 | 仓库删除受限 | MEDIUM | 谁持有 Delete repository 却不管理该仓库 |
| 1.3.1 | 不活跃用户被移除 | MEDIUM | 每个用户的最后访问时间，以及从未接受的邀请（Services） |
| 1.3.3 | 组织管理员人数有界（2–5） | HIGH | Project Collection Administrators，组已展开 |
| 1.3.7 | 每个仓库至少 2 名管理员 | LOW | 谁持有 Manage permissions，组织管理员除外 |
| 1.3.8 | 默认仓库访问受限 | MEDIUM | 项目可见性，以及「所有人」组持有的、超出 `everyoneAllowedPermissions` 的权限 |
| 1.5.1 | 推送的机密会被拦截 | MEDIUM | Advanced Security 机密保护并开启「Block secrets on push」（Services） |

另有 3 条以明确记录的人工检查形式保留——会被报告、说明，并排除在评分之外：

| CIS | 规则 | 为什么不自动判定 |
|---|---|---|
| 1.1.6 | 代码所有者 | Azure Repos 没有 CODEOWNERS。必需且带路径过滤的「Automatically included reviewers」是对应机制，报告会列出找到的那些——但哪些路径敏感是一个没有 API 能回答的判断。 |
| 1.3.5 | 强制多因素认证 | 由 Microsoft Entra 条件访问（或 Server 前面的目录服务）强制，Azure DevOps API 并不暴露。基于 Azure DevOps 数据的判定只能是编造的。 |
| 1.3.9 | 组织已验证 | Azure DevOps 没有「已验证组织」的概念。输出 `NA`。 |

```bash
azure-devops-bench list-checks          # 全部规则，含严重度与作用范围
azure-devops-bench list-checks --json   # 完整元数据，含修复说明
```

### Azure Repos 里是什么在保护分支

Azure Repos 没有自己的分支限制；分支靠**必需的分支策略**来保护，而保护力度只取决于它们
约束了谁。扫描从两方面推导保护：

- **直接推送**（1.1.15）：只要有任一必需的分支策略作用于默认分支，就会被阻止。持有
  *Bypass policies when pushing* 的人不受约束。
- **Force push**（1.1.16）需要 *Force push*；在必需策略下还需要推送绕过权限。Azure Repos
  会授予分支创建者对该分支的 Force push，所以第一个推送 `main` 的人可以改写它，除非这项
  授权被收回——扫描会读取分支级权限并把他们计算在内。
- **删除**（1.1.17）：必需策略会阻止删除，除非同时持有 Force push 与推送绕过权限；没有必需
  策略时，任何持有 Force push 的人都能删除该分支。
- **拉取请求绕过**（1.1.5）是 *Bypass policies when completing pull requests*；**管理员**
  （1.1.14）是持有任一绕过权限、同时又管理该仓库或组织的人。

哪些策略生效，以服务器的回答为准——针对仓库及其默认分支的 `git/policy/configurations`，
涵盖项目级、前缀以及「每个仓库的默认分支」等作用范围——并如前所述与项目的全部策略列表交叉
核对。可选（非 *Required*）的策略会出现在证据里，但不提供任何保护。

谁持有某项权限，以服务器自己的计算（`effectiveAllow`）为准：对从组织一直到分支任何一级上
有条目的每个身份都做计算，组展开到具体的人，个人的显式拒绝会被扣除。判定最终数的是人：

```yaml
thresholds:
  maxBypassPrincipals: 0                    # 允许多少人绕过保护
allowedBypassPrincipals: [Project Collection Build Service (fabrikam)]   # 不计入的那些
```

`allowedBypassPrincipals` 应该最先考虑：构建身份往往确实需要越过策略推送，如果没有地方声明
这一点，阈值就得调高到足以掩盖真人的程度。一个已经超过阈值的下界会判失败；没超过的则输出 `MANUAL`。

CIS-1.1.12 **默认判失败**：Azure Repos 自己无法验证提交签名，唯一的强制手段是由能验证签名
的服务发布的必需状态检查——而那是哪个服务，取决于你的部署。请在 `signatureStatusChecks` 中
写明它（`genre/name` 或 `name`）。

被禁用的仓库只会被记录，不发出任何一个 Git 请求；在默认开启的 `skipArchivedRepositories` 下
它们不参与评估，关闭该选项时，它们的变更类规则输出 `NA`。空仓库的同一批规则也输出 `NA`。

---

## 评分

```
score = ⌊ Σ weight(passed) / Σ weight(passed + failed) × 100 ⌋
```

其中 `HIGH = 3`、`MEDIUM = 2`、`LOW = 1`。`MANUAL` 与 `NA` 不计入任何一边。分数向下取整，
从不四舍五入：99.9 就是 99，所以 100 永远意味着每一个已判定的发现都通过了。

表格输出会把算式打印出来（`weighted 73/136 (HIGH=3, MEDIUM=2, LOW=1; manual and n/a
excluded)`），让这个数字可以核对，而不必靠信任。**什么都无法判定**时分数是 `0` 而不是 `100`。
请把分数当作趋势线；决定结果是否可以接受的，是按严重度统计的失败。

---

## 输出格式

**`table`**（默认）——按行组织的发现报告：每条失败是一条自成一体的记录，结尾是评分块。

```
azure-devops-bench v0.1.0  ·  https://dev.azure.com/fabrikam  ·  2026-10-01 00:00:00 UTC

Fabrikam-Fiber/legacy-portal  CIS-1.1.3 HIGH: Pull requests into master require 0 independent
    approval(s); at least 2 are needed.
    fix: Require 2+ reviewers at Project settings -> Repositories -> <repo> -> Policies.
    · independent approvals required: 0 (minimumApproverCount 0)

...

Fabrikam-Fiber/legacy-portal  CIS-1.1.16 HIGH: alice@fabrikam.com can force push master, rewriting
    or erasing the history reviewers approved.
    fix: Remove "Force push" at Repos -> Branches -> <default branch> -> Branch security.
    · can force push: alice@fabrikam.com
    · 1 in total; thresholds.maxBypassPrincipals is 0

...

Fabrikam-Fiber/legacy-portal  CIS-1.1.5 MEDIUM: bob@fabrikam.com, chen@fabrikam.com can complete
    pull requests into master without the approvals and checks its policies require.
    fix: Revoke "Bypass policies when completing pull requests" at Project settings -> Repositories.
    · Bypass policies when completing pull requests: bob@fabrikam.com, chen@fabrikam.com
    · 2 in total; thresholds.maxBypassPrincipals is 0
    · through groups: [Fabrikam-Fiber]\Release Managers

... one record per failing resource and control, severity descending ...

CIS-1.3.5 MANUAL (instance): Multi-factor authentication is enforced by Microsoft Entra ID
    Conditional Access (or the directory in front of Azure DevOps Server), which the Azure DevOps
    API does not expose. Verify enforcement there.
    fix: Require MFA with Conditional Access at Entra admin center -> Protection -> Conditional
    Access.

...

8 controls could not be read (Unread) on Fabrikam-Fiber/shared-infra; see Scan warnings below.

Scan warnings

  - group "[fabrikam]\Platform Engineers (Entra)" is a Microsoft Entra group; Azure DevOps lists its
    members only once they have signed in, so counts derived from it are lower bounds

Rules

  CIS-1.1.3   https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-policies#require-a-minimum-number-of-reviewers

... one line per control in the report, with Microsoft's documentation page ...

SCORE 53/100   39 passed  32 failed  14 manual  15 n/a
      20 controls failed across 32 findings
      weighted 73/136 (HIGH=3, MEDIUM=2, LOW=1; manual and n/a excluded)
      scored 71 of 85 findings (83%); 14 could not be evaluated
```

以上是 `azure-devops-bench scan --demo` 在 `COLUMNS=100` 下的真实输出，标有 `...` 的地方做了删节。

**一条失败就是一条记录**：`<资源> <规则 ID> <严重度>: <详情>`，下面缩进一行修复建议，再下面是
以 `·` 开头的证据——所以 `grep 'HIGH:'` 就是严重发现的清单，每一条都自带上下文。
**需要人来判断的规则各聚合成一行**，按规则与原因分组。扫描*读不到*的内容合并成扫描警告上方
的一句话，原因写在警告里。`Rules` 在发现之后为每条规则列出微软的文档页面；如果某条规则在一个
项目的所有仓库上都失败，它会说明一项项目级设置就能一次修好全部。

`--details` 改为按资源输出表格，并附上完整的修复段落；`--details=Fabrikam-Fiber/payments-api`
或 `--details=CIS-1.1.9` 可以缩小范围。`--show-passed` 连通过的规则也列出，`--no-remediations`
去掉修复建议，`--max-resources` 限制按资源输出的段落数。颜色只在终端上使用，并遵守
`NO_COLOR`。工具输出只有英文，这是一个决定：判定文字由规则自己拼装，换一种语言意味着在每条
规则里再复制一份消息拼装逻辑。

**`json`** —— 完整报告：每条发现、证据、规则存在的理由、修复说明、接受它的例外（如有），以及评分明细。

**`sarif`** —— 供代码扫描使用的 SARIF 2.1.0。输出失败与需人工审查的结果，不输出通过与 `NA`。
每个结果都带有 `physicalLocation`——GitHub code scanning 会悄悄丢弃没有它的结果——其 URI 由平台、
组织与仓库组成（`azure-devops/dev.azure.com/fabrikam/Fabrikam-Fiber/payments-api`），旁边的
`logicalLocation` 说明它真正指什么。结果带有指纹，告警在多次运行之间保持稳定；
`automationDetails` 区分上传到同一仓库的不同组织；被接受的发现带有 `suppressions` 条目；
扫描警告以通知的形式传递，因此不完整的扫描绝不会被误认为干净的扫描。遵守 GitHub 每次运行
5,000 个结果的上限：保留最严重的，并说明扣下了多少。

**`junit`** —— JUnit XML，供原生展示测试结果的 CI 使用：Azure Pipelines 的
*Publish Test Results*、Jenkins、GitLab。每条规则一个 suite，每个资源一个测试用例；未被接受的
`FAIL` 是失败，`MANUAL`、`NA` 与被接受的发现标为跳过并附原因；漏掉项目的扫描会多出一个
失败的 `scan` suite。

报告与快照一样以 `0600` 权限、原子方式写入：报告点名了每一个能被 force push 的仓库、每一个
早该移除的账号，而 CI 步骤绝不能把写了一半的报告当成完整报告来读。

---

## 配置

凡是合理的人可能持不同意见的阈值都可以配置；描述部署本身而非某一次运行的设置——退出阈值、
传输、并发、进度显示——也都放在这里，而不是命令行参数里。

```bash
azure-devops-bench init            # 生成带注释、包含全部键的 azure-devops-bench.yaml
azure-devops-bench scan            # 自动在工作目录中找到它
```

查找顺序：给了 `--config` 就用它，否则是工作目录里的 `azure-devops-bench.yaml`（或
`.azure-devops-bench.yaml`），再否则是用户配置目录下的 `config.yaml`。实际使用的文件总会在
stderr 上点名：一个拉取请求放进工作目录的配置文件会改变 CI 关卡如何评判组织，不能悄无声息地
发生。`--set` 可在单次运行中覆盖任意键（`--set scan.failOn=none`、
`--set thresholds.minApprovers=1`）。

完整的带注释配置见 [`examples/config.yaml`](examples/config.yaml)。最常调整的：

```yaml
scan:
  failOn: high            # 达到或超过该严重度时退出 1：high、medium、low、none
  maxManual: -1           # 可自动判定的发现中未读到的比例超过该百分比时退出 1；-1 关闭
  concurrency: 4          # 并行抓取的仓库数，所有项目共用
  caFile: ""              # 追加到系统根证书的 PEM 证书包（内部 CA 后面的 Server）
  allowIncomplete: false  # true：有项目的仓库无法列出时不以 2 退出

thresholds:
  minApprovers: 2          # CIS-1.1.3
  staleBranchDays: 90      # CIS-1.1.8
  inactiveUserDays: 90     # CIS-1.3.1
  minOrgAdmins: 2          # CIS-1.3.3
  maxOrgAdmins: 5
  minRepositoryAdmins: 2   # CIS-1.3.7
  maxBypassPrincipals: 0   # CIS-1.1.5、1.1.14–1.1.17；-1 关闭绕过检查
  maxRepositoryCreators: 0 # CIS-1.2.2

allowedBypassPrincipals: [Project Collection Build Service (fabrikam)]
signatureStatusChecks: [security/verify-signatures]   # 为空时 CIS-1.1.12 判失败
everyoneAllowedPermissions: [GenericRead]             # CIS-1.3.8
exclude: [CIS-1.1.13]                                 # 或用 include: 只运行一部分
```

配置文件只需写出它要改的部分；列表会整体替换默认值。无法识别的键是错误而不是被忽略——
否则把 `minApprovers` 写成 `minApprover` 能顺利解析、什么都没改，读者却以为报告是按他们的阈值
评估的。空的列表项、负数阈值、以及不对应任何 Git 权限的 `everyoneAllowedPermissions` 条目也一样。

### 例外

有些发现是已知且被接受的——即将下线的遗留仓库、必须推送的构建身份。例外记录下这一决定，
并附上原因与截止日期：

```yaml
exceptions:
  - control: CIS-1.1.16
    resources: [Fabrikam-Fiber/legacy-*]   # glob；* 不跨越 "/"；组织级规则用 "instance"
    reason: Read-only mirror, retired with the Q1 migration
    owner: platform-team@fabrikam.com
    expires: 2027-03-31                     # 生效至当天结束（UTC）
```

被接受的发现**仍会被报告、仍是 `FAIL`、仍计入分数**——分数描述的是组织，接受一个发现并不会
改变组织。它不再做的，是让运行因 `scan.failOn` 而失败（对 `MANUAL` 发现而言，则是不再计入
`scan.maxManual`）。表格把被接受的发现列在单独的标题下，附原因与截止日期；JSON 中带有
`waiver`，SARIF 中带有 `suppressions` 条目，JUnit 中标为跳过。

没有原因和截止日期就没有例外。例外过期后，对应发现会再次让运行失败，并且无论 verbose 与否，
扫描都会在 stderr 上说明原因；一条什么都没匹配到的例外——发现已修复，或仓库已改名——也会被
报告出来，以便删除。

---

## 在 CI 中使用

阈值写在与流水线一起提交的 `azure-devops-bench.yaml` 里，流水线和笔记本读的是同一个文件，
两者在任何事情上都不会有分歧：

```yaml
# azure-devops-bench.yaml
scan:
  failOn: high
  maxManual: 40
```

**Azure Pipelines** —— 结果通过 `PublishTestResults` 显示在运行的 *Tests* 标签页：

```yaml
- script: |
    azure-devops-bench scan --url "$(System.CollectionUri)" \
      -o junit --output-file "$(Agent.TempDirectory)/azure-devops-bench.xml"
  displayName: Audit Azure DevOps
  env:
    AZURE_DEVOPS_TOKEN: $(AUDIT_TOKEN)   # 机密变量：PAT，或扫描用服务主体的 Entra token

- task: PublishTestResults@2
  condition: succeededOrFailed()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: $(Agent.TempDirectory)/azure-devops-bench.xml
    testRunTitle: azure-devops-bench
    failTaskOnFailedTests: false   # the scan's exit code is the gate
```

token 是 PAT，或按 [token 需要什么权限](#token-需要什么权限) 配置好的服务主体的
Microsoft Entra token。流水线自身的身份 `$(System.AccessToken)` 特意没有作为推荐：除非放宽过
相应设置，它只限于流水线所在的项目；而它背后的构建服务身份能否读取本扫描依赖的权限、Graph 与
授权 API，尚未经过验证。读不到时扫描输出 `MANUAL` 而不是错误的判定，所以尝试是安全的，但要
预期会有缺口。机密变量只能像上面那样通过 `env:` 传给脚本。

**GitHub Actions** —— 把 SARIF 上传到 code scanning。扫描发现问题时以 `1` 退出，这正是它的
用意，但那样作业会在上传之前就结束；因此失败被推迟到最后一步。上传需要作业 `permissions` 中的
`security-events: write`——在私有仓库中还需要 `actions: read` 与 `contents: read`。

```yaml
- name: Audit Azure DevOps
  id: audit
  continue-on-error: true
  run: |
    azure-devops-bench scan --url "${{ vars.AZURE_DEVOPS_URL }}" \
      -o sarif --output-file azure-devops-bench.sarif
  env:
    AZURE_DEVOPS_TOKEN: ${{ secrets.AZURE_DEVOPS_TOKEN }}

- name: Upload to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: azure-devops-bench.sarif
    category: azure-devops-bench

- name: Fail the job if the audit did
  if: steps.audit.outcome == 'failure'
  run: exit 1
```

告警会落在每个结果 `physicalLocation` 中的合成路径上，而不是仓库里的某个文件，因为发现是
一项设置，而不是一行代码；如果是给仪表盘提供数据，`json` 是更好的输入。

**Jenkins** —— JUnit 发布器在构建的测试视图里展示结果：

```groovy
stage('Audit Azure DevOps') {
  steps {
    withCredentials([string(credentialsId: 'azure-devops-bench-token', variable: 'AZURE_DEVOPS_TOKEN')]) {
      sh '''
        azure-devops-bench scan --url https://dev.azure.com/fabrikam \
          -o junit --output-file azure-devops-bench.xml
      '''
    }
  }
  post {
    always {
      // Draws the report; the scan's exit code has already decided the build.
      junit testResults: 'azure-devops-bench.xml', allowEmptyResults: true, skipMarkingBuildUnstable: true
    }
  }
}
```

在每个示例中，**由扫描的退出码决定构建结果，报告只负责展示。** 测试报告承担不了关卡的职责：
JUnit 没有严重度的概念，所以每个未被接受的 `FAIL` 都是一个失败的测试——包括 `LOW`——任由
发布器因失败的测试让构建失败，等于按比 `failOn` 更严格的标准设卡。而丢掉扫描退出码，则会放过
被突破的 `maxManual` 或 `failUnder`——要么是黄色构建（Jenkins 的 `junit` 步骤把失败的测试
标为 `UNSTABLE` 而不是失败），要么在恰好没有测试失败时直接是绿色构建。

退出码：

| 退出码 | 含义 |
|---|---|
| `0` | 扫描完成，未触发任何阈值 |
| `1` | 扫描完成，触发了某个阈值 |
| `2` | 扫描无法完成——或无法为它的覆盖范围作保 |

三项设置决定退出码 `1`，它们回答的是不同的问题：

| 设置 | 回答的问题 |
|---|---|
| `scan.failOn` | 是否有这么严重的失败？`high`（默认）、`medium`、`low`、`none` |
| `scan.failUnder` | 分数是否可以接受？0–100；`0` 关闭 |
| `scan.maxManual` | 扫描看到的内容是否足以下结论？一个百分比；`-1` 关闭 |

从 `failOn: high` 开始，在第一轮发现清理完之后再收紧；不会被清理的发现，交给[例外](#例外)。

`scan.maxManual` 值得尽早设置。读不到的发现会被排除在分数之外，而不是计为失分——对单条规则
是对的，汇总起来却会误导：丢了一个 scope 的 token 会缩小分母，分数可能比正常的 token 还*高*。
`scan.failUnder` 抓不到这种情况，`scan.maxManual` 可以。

退出码 `2` 涵盖配置错误或凭据被拒绝、未知的 `--project` 或 `--repository`、某条规则评估出错
——以及两种虽然跑完了、却无法为覆盖范围作保的扫描：**一个仓库都没有评估**（token 读不了的
`--project`、什么都看不到的 token、所有仓库都被禁用的组织），以及**有项目的仓库无法列出**——
这些仓库于是从报告中消失，且没有任何发现提到它们。报告仍会写出，并且自己会说明这一点：
SARIF 运行被标记为不成功并附带一条错误通知，JUnit 文件里多出一个失败的 `scan.coverage` 用例。
若确属有意，可用 `scan.allowIncomplete: true` 接受第二种情况。

### 把抓取与评估分开

快照是自包含的产物，所以持有凭据的步骤与做评估的步骤可以是不同的步骤，在不同的机器上：

```bash
# 在能访问 Azure DevOps 且持有 token 的 runner 上
azure-devops-bench scan --snapshot-out snapshot.json -o json --set scan.failOn=none

# 之后在任何地方——无需凭据，无需网络
azure-devops-bench scan --snapshot-in snapshot.json -o sarif
```

快照以 `0600` 写入：它们是一份组织薄弱点的精确地图。报告和保存下来的 `instance.yaml` 也一样。
这是 Unix 权限位——在 Windows 上文件继承所在目录的 ACL，所以请把快照和报告放在本就受限的位置。

### 不再扫描就能追问

每次网络扫描都会留下它的快照（`0600`，每个组织一份，放在用户配置目录下），`--last` 重新渲染
最近的那一份：

```bash
azure-devops-bench scan                     # 总览；快照被保留下来
azure-devops-bench scan --last --details    # 展开细节，不再访问 Azure DevOps
```

`--last` 运行会说明快照来自哪个组织、有多旧，超过一天会给出警告。`scan.cache: false` 让快照不落盘。

### 捕捉退化

`diff` 用当前的构建与配置评估两份快照，并报告变化：

```bash
azure-devops-bench diff last-week.json today.json
```

只有 `PASS → FAIL` 算退化并以 `1` 退出（`--fail-on-regression=false` 使其只报告不失败）。
新出现的仓库带着失败不算退化，涉及 `MANUAL` 的变化也不算——token 丢了 scope 是扫描的盲区，
不是组织变差了。比较两个不同组织的快照会被拒绝，除非用 `--allow-other-instance` 表明是有意为之。

---

## 工作原理

```
Azure DevOps REST  ──►  fetcher  ──►  snapshot.json  ──►  Rego policies  ──►  report
                     (Go, GET only)   (normalized)      (one per control)   table/json/sarif/junit
```

- **fetcher 从不做判定。** 它只做归一化——解析策略作用范围、计算权限、展开组——并记录它
  读不到什么，以及它交出的每个集合有多确定。
- **策略从不发 HTTP 请求。** 它们读取一份 JSON 文档并返回判定，先检查可用性，再检查设置。

整个过程不依赖 Azure SDK：客户端是一个小巧的只读 HTTP 客户端，它能发出的每个请求都在一个
文件里一目了然。包结构、策略契约、如何新增规则以及如何运行两套测试，见
[CONTRIBUTING.md](CONTRIBUTING.md)；fetcher 对未成文行为所做的推断，以及核实它们的探针，见
[`hack/recon`](hack/recon/README.md)。

---

## 遵循的规范

四种状态、「无法判定的规则输出 `MANUAL`」这一条、`metadata.json` 的字段、评分公式、快照 schema
以及 SARIF 的形态，都在家族的总仓库 [scm-bench](https://github.com/scm-bench/scm-bench) 中
规定。构建时不从那里导入任何东西。

| 文档 | 规定了什么 |
| --- | --- |
| [bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md) | 每个 bench 共有的部分，无论它审计什么。 |
| [SCM 快照 schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md) | `snapshot.json` 的形态，与 bitbucket-bench 共用。Azure DevOps 以增量方式加入了 Bitbucket 没有对应物的字段——谁可以绕过策略、Advanced Security。 |
| [config conventions](https://github.com/scm-bench/scm-bench/blob/main/docs/config-conventions.md) | 配置文件在哪里查找，以及各键如何合并。 |

---

## 路线图

**v0.2** —— 把 [recon](hack/recon/README.md) 的抓取结果作为测试夹具回放，逐条撤下被它们证实
或证伪的推断；把审计流作为日志类规则的证据；在微软为组织安全策略提供文档化的 API 之后支持它们。

---

## 许可证

Apache 2.0。见 [LICENSE](LICENSE)。
