# [领域-5](#domain-5-identity-and-access-management-iam) **身份与访问管理 (Identity and Access Management, IAM)**

身份与访问管理 (Identity and Access Management, IAM) 领域关注于授予和撤销访问数据或在系统上执行操作的权限相关的问题，约占考试内容的 13%。

- 资产包括信息、系统、设备、设施和应用程序，组织使用物理和逻辑访问控制来保护它们。
- **访问控制 (Access control)**：协同工作的机制集合，用于保护组织资产，允许受控地访问授权主体，允许管理层指定哪些用户可以访问哪些资源，以及他们可以执行哪些操作；提供个人问责制。
- **访问控制原则**：需要知道 (need to know)、最小权限 (least privilege)和职责分离 (separation of duties)。
- **访问控制服务**：(又称 AAA 服务 (AAA services)) 身份识别 (identification)、认证 (authentication)、授权 (authorization)和问责 (accountability)。
- **认证 (Authentication)**：通过将一个或多个认证因素与存储用户认证信息的数据库进行比较来验证主体的身份；主体通过提供认证凭证来证明其身份。
- **认证器保证级别 (Authenticator Assurance Levels, AAL)**：衡量认证过程稳健性的指标；AAL 级别从 AAL1 (最不稳健) 到 AAL3 (最稳健) 进行排名，并在 [NIST 800-63-3b](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf) 中有详细描述。
  - AAL1 (某种程度上保证用户控制与其账户相关的认证器)：允许单因素或多因素认证，对认证器类型的要求不那么严格。
  - AAL2 (高可信度)：需要多因素认证 (Multi-Factor Authentication, MFA)，并且必须能抵抗重放攻击。
  - AAL3 (非常高的可信度)：需要基于硬件的多因素认证 (Multi-Factor Authentication, MFA)，并强制要求验证器具有防模拟和防网络钓鱼的能力。
- **问责制 (Accountability)**：在认证主体后，系统根据其已证实的身份授权对客体的访问；审计日志和审计跟踪记录事件，包括执行操作的主体的身份；有效的身份识别、认证和审计相结合，提供了问责制；请注意，**访问控制的原则**是问责制。
- 三种主要的认证因素是：知识认证 (你知道什么)、所有权认证 (你拥有什么) 和特征认证 (你是什么)。
  - 你知道什么：类型 1 认证 (密码、口令、PIN 等)
  - 你拥有什么：类型 2 认证 (身份证、护照、智能卡、令牌、PC 上的 cookie 等)
  - 你是什么：类型 3 认证，包括生物识别技术 (指纹、虹膜或视网膜扫描、面部几何形状等)
  - 你在哪里：类型 4 认证 (IP/MAC 地址)
  - 你做什么：类型 5 认证 (签名、图案解锁)
- 单点登录 (Single Sign-On, SSO) 技术允许用户一次性认证，即可访问网络或云中的任何资源，无需再次认证。
- **访问控制系统 (Access Control System)**：确保对资产的访问是经过授权并根据业务和安全要求受到限制的。
- **访问控制令牌 (Access Control Token)**：基于时间、日期、星期等参数，令牌定义了对系统的访问有效性。
- **ADFS (Active Directory Federation Services)**：身份访问解决方案，为客户端计算机 (无论在网络内部还是外部) 提供对受保护的面向互联网的应用程序或服务的无缝 SSO (Single Sign-On) 访问，即使用户账户和应用程序位于完全不同的网络或组织中。
- **异步令牌 (Asynchronous token)** (通过所有权硬/软令牌进行认证)：涉及挑战和响应；它们更复杂 (也更昂贵)，但也更安全 (参见同步令牌)。
- **缓存投毒 (Cache poisoning)**：向缓存中添加非预期元素的内容 (例如网页)；一旦被投毒，合法的网页文档可能会调用缓存项，从而激活恶意缓存。
- **能力表 (Capability tables)**：列出分配给主体的权限，并识别主体可以访问的客体。
- **CAPTCHA (Completely Automated Public Turing test to tell Computers and Humans Apart)**：全自动区分计算机和人类的公开图灵测试，是一种用于防止账户自动创建、垃圾邮件和暴力破解密码攻击的安全措施。
- **中央认证服务 (Central Authentication Service, CAS)**：中央认证服务 (一种 SSO (Single Sign-On) 实现)。
- **内容相关控制 (Content-dependent control)**：内容相关访问控制在身份识别和认证之外增加了额外的标准：主体试图访问的实际内容；一个组织的所有员工都可以访问人力资源数据库查看他们累积的病假和年假时间，但如果员工试图访问首席信息官的人力资源记录内容，则访问将被拒绝。
- **上下文相关访问控制 (Context-dependent access control)**：在授予访问权限之前应用额外的上下文，时间是常用的上下文。
- **交叉错误率 (Crossover Error Rate, CER)**：识别生物识别方法的准确性，是给定传感器在给定系统和上下文下，错误接受率 (False Acceptance Rate, FAR, or Type 2) 等于错误拒绝率 (False Rejection Rate, FRR, or Type 1) 的点；如果两种类型错误的潜在影响相等，则这是最佳操作点。
- **跨站请求伪造 (Cross-Site Request Forgery, CSRF)**：(又称 XSRF) 是一种强迫经过认证的用户向他们当前已认证的 Web 应用程序提交请求的攻击；在 CSRF 攻击中，预定目标是 Web 应用程序本身；攻击利用了 Web 应用程序对用户浏览器的信任，通过欺骗已认证的用户提交伪造的请求，攻击者可以使 Web 应用程序执行操作，就像是合法用户发起的一样。
- **错误拒绝率 (False Rejection Rate, FRR)**：错误拒绝率 (类型 1) 是错误地拒绝合法身份认证从而拒绝访问的概率；以百分比表示。
- **错误接受率 (False Acceptance Rate, FAR)**：错误接受率 (类型 2) 是错误地将声称的身份认证为合法，并在此基础上识别和授予访问权限的概率；以百分比表示。
- **道德墙 (Ethical Wall)**：使用管理、物理/逻辑控制来建立/强制信息、资产或工作职能的分离，以满足"需要知道"的边界或防止利益冲突的情况；又称区划 (compartmentalization)。
- **控制粒度 (Granularity of controls)**：安全功能可以配置或调整性能和灵敏度的抽象或细节级别。
- **身份即服务 (Identity as a Service, IDaaS)**：基于云的服务，为客户本地和/或云中的目标系统代理 IAM (Identity and Access Management) 功能；指在基于云的环境中实施/集成身份服务；服务包括配置、管理、SSO (Single Sign-On)、MFA (Multi-Factor Authentication)、目录服务，无论是在本地还是在云中。
- **身份识别 (Identification)**：主体声称或表明身份的过程；主体通过身份识别来声明身份。
- **身份验证 (Identity proofing)**：又称注册 (registration)，是确认某人是其声称的身份的过程；收集/验证请求访问/凭证/特殊权限的人的信息以与该人建立关系的过程；身份验证包括基于知识的认证和认知密码，用户会被问及一系列只有他们才知道的问题。
- **基于知识的认证 (Knowledge-Based Authentication, KBA)**：根据用户在权威来源中记录的历史，向用户询问一系列问题的过程；例如，银行向客户询问一系列关于他们过去居住地址和当前汽车/抵押贷款支付金额的问题。
- **存储卡 (Memory card)**：通过所有权因素进行认证，通常使用磁条作为存储器，每次交易都从磁条中读取相同的数据。
- **客体 (Objects)**：主体访问的东西，例如文件；用户是在执行某些操作或完成任务时访问客体的主体。
- **密码认证 (Passwords authentication)**：最弱的认证形式，但密码策略通过强制执行复杂性和历史要求来帮助提高安全性。
- **策略执行点 (Policy Enforcement Point, PEP)**：接收认证请求的应用程序组件，充当网守，将请求发送给 PDP (Policy Decision Point)；一旦 PDP 提供决策，PEP 就会执行它 (授予/拒绝)。
- **策略决策点 (Policy Decision Point, PDP)**：根据预定义的规则对从 PEP (Policy Enforcement Point) 发送的认证请求做出决策。
- **自助身份管理 (Self-service identity management)**：身份管理生命周期中最终用户 (相关身份) 可以自行发起或执行的元素 (例如密码重置、更改挑战问题等)。
- **服务器端请求伪造 (Server-Side Request Forgery, SSRF)**：如果 API 在未验证用户提供的 URI 的情况下获取远程资源，则此漏洞允许攻击者利用应用程序向意外目标发送精心制作的请求 (无论防火墙/VPN 保护如何)。
- **SESAME (Secure European System for Applications in a Multi-Vendor Environment)**：多厂商环境中应用的安全欧洲系统，是 Kerberos 的改进版本；一种用于 SSO (Single Sign-On) 的协议 (如 Kerberos)，但其优点是支持对称和非对称加密 (因此解决了 Kerberos 的密钥分发问题)；它还发布多个票据，以减轻像 TOCTOU (Time-of-Check to Time-of-Use) 这样的攻击。
- **会话 (Session)**：成功进行用户身份识别、认证和授权过程后创建的内容；表示用户和系统之间的连接和交互。
- [**身份七定律**](https://www.ipc.on.ca/en/media/1525/download?attachment):
  - 1: 用户控制和同意：身份系统只能在用户同意的情况下泄露用户身份信息。
  - 2: 有限用途的最小化披露：身份系统应尽可能少地披露身份信息。
  - 3: 合理方：系统只应向有合理需要的方披露信息。
  - 4: 定向身份：强调需要公共和私有标识符，让个人控制自己的身份以及如何建立信任。
  - 5: 运营商和技术的多元化：身份系统应通过商定的协议和统一的用户体验进行互操作。
  - 6: 人机集成：企业应在系统和用户之间建立非常可靠的通信，并定期测试保障措施。
  - 7: 跨上下文的一致体验：统一的身份系统应保证用户简单、一致的体验，允许用户决定在什么上下文中使用什么身份。
- **智能卡 (Smart card)**：通过所有权因素进行认证，包含一个嵌入式集成电路 (Integrated Circuit, IC) 芯片，每次交易都会生成唯一的认证数据 (参见存储卡)。
- **分割响应攻击 (Split-response attack)**：导致客户端下载非请求网页预期元素的内容，并将其存储在浏览器缓存中的攻击。
- **主体 (Subject)**：访问被动客体的实体，例如用户。
- **同步令牌 (Synchronous token)** (通过所有权硬/软令牌进行认证)：令牌生成器和认证服务器每 30-60 秒生成相同的令牌或一次性密码 (参见异步令牌)。
- **模板 (Template)**：某人独特生物特征的数字表示 (即表示生物特征数据的一次性数学函数)；模板可用作"1:N"进行身份识别 (其中用户的模板用于搜索用户的身份)，或"1:1"进行认证 (其中用户被识别，模板用作认证用户的因素)。
- **捕鲸攻击 (Whaling attack)**：针对拥有大量资产的高层官员/私人，授权大额资金电汇的网络钓鱼攻击。
- **跨站脚本 (Cross-Site Scripting, XSS)**：跨站脚本 (XSS) 基本上利用反射输入来欺骗用户的浏览器执行来自受信任站点的非受信任代码；这些攻击是一种注入类型，其中恶意脚本被注入到原本良性和受信任的网站中；XSS 攻击发生在攻击者使用 Web 应用程序向不同的最终用户发送恶意代码 (通常以浏览器端脚本的形式) 时；允许这些攻击成功的缺陷非常普遍，并且发生在 Web 应用程序在未验证或编码的情况下使用用户输入生成输出的任何地方。
- **跨站跟踪 (Cross-Site Tracing, XST)**：跨站跟踪 (XST) 攻击涉及使用跨站脚本 (XSS (Cross-Site Scripting)) 和 TRACE 或 TRACK HTTP 方法；这可能允许攻击者窃取用户的 cookie。

## [5.1](#51-control-physical-and-logical-access-to-assets-osg-10-chpt-13) 控制对资产的物理和逻辑访问 (OSG-10 第 13 章)

- 控制对资产的访问 (资产是对组织有价值的任何东西)；有形资产是你可以触摸的东西，无形资产是像信息和数据这样的东西；控制对资产的访问是安全的核心主题。
- 了解没有物理安全就没有安全：没有对物理环境的控制，管理、技术和逻辑访问控制是无效的。
- 了解你拥有什么资产，以及如何保护它们。
  - **物理安全控制 (physical security controls)**：例如周边安全和环境控制。
    - 控制访问和环境
  - **逻辑访问控制 (logical access controls)**：根据验证所呈现的身份与先前批准的身份相匹配来认证或拒绝访问的自动化系统；用于保护对信息、系统、设备和应用程序的访问的技术控制。
    - 包括认证、授权和权限
    - 权限有助于确保只有授权实体才能访问数据
    - 逻辑控制将对系统/网络上的配置设置的访问限制为仅限授权个人
    - 适用于本地和云
- 除了人员之外，资产可以是信息、系统、设备、设施、应用程序或服务。

- 5.1.1 信息
  - 组织的信息包括其所有数据，存储在简单的文件 (在服务器、计算机和小型设备上) 或数据库中。

- 5.1.2 系统
  - 组织的系统包括提供一个或多个服务的任何东西；带有数据库的 Web 服务器就是一个系统；分配给用户和系统帐户的权限控制系统访问。

- 5.1.3 设备
  - 设备指任何计算系统 (例如路由器和交换机、智能手机、笔记本电脑和打印机)；自带设备 (Bring Your Own Device, BYOD) 已被越来越多地采用，存储在设备上的数据仍然是组织的资产。

- 5.1.4 设施
  - 任何物理位置、建筑物、房间、综合体等；物理安全控制对于帮助保护设施非常重要。

- 5.1.5 应用程序
  - 应用程序提供对数据的访问；权限是限制对应用程序的逻辑访问的简单方法。

- 5.1.6 服务
  - 身份管理的要点是控制对任何资产的访问，包括数据、系统和服务；服务包括广泛的过程功能，例如打印、最终用户支持、网络容量等；如上所述，访问控制对于保护这些服务非常重要。

## [5.2](#52-design-identification-and-authentication-strategy-eg-people-devices-and-services-osg-10-chpt-13) 设计身份识别和认证策略 (例如，人员、设备和服务) (OSG-10 第 13 章)

- **身份识别 (Identification)**：主体声称或表明身份的过程。
- **认证 (Authentication)**：通过知识、所有权或特征验证身份来验证主体的身份；将一个或多个因素与有效身份数据库 (例如用户帐户) 进行比较。
  - 认证的一个核心原则是所有主体必须具有唯一的身份。
  - 身份识别和认证作为单个两步过程一起发生。
  - 用户用用户名识别自己，并用密码认证 (或证明其身份)。

- 5.2.1 组和角色
  - **角色 (Roles)**：与组织内的工作职能相对应的权限集，而不是用户组；用户被分配一个角色，并被授予与该角色相关的权限。
    - 另一种说法是，角色是以功能为中心的，例如，一级帮助台分析师是一个定义了可用特定权限的特定角色。
    - 基于角色的访问意味着创建一个具有特定权限的角色，然后将其分配给该角色或工作中的某人。
  - **组 (Groups)**：组是用户的集合，管理员可以向组分配权限，而不是向单个用户分配权限；这使得管理大量用户变得更加容易。
    - 组是以用户为中心的，关注该用户组的集体身份。
  - 身份和访问管理是用于控制对关键资产访问的流程和技术的集合；其目的是管理对信息、系统、设备和设施的访问。
  - 身份管理 (Identity Management, IdM) 实施技术通常分为两类：
    - **集中式访问控制 (centralized access control)**：意味着系统中的单个实体执行所有授权验证。
      - 可能会产生单点故障
      - 小团队可以初步管理，并可以扩展到更多用户
    - **分散式访问控制 (decentralized access control)**：(又称分布式访问控制) 意味着遍布系统中的多个实体执行认证验证。
      - 需要更多个人或团队来管理，并且管理可能分散在许多位置
      - 难以保持一致性
      - 对任何单个访问控制点所做的更改都需要在其他地方重复
  - 随着无处不在的移动计算和随时随地的访问 (对应用程序和数据)，身份是"新的边界"。

- 5.2.2 认证、授权和审计 (Authentication, Authorization and Accounting, AAA) (例如，多因素认证 (Multi-Factor Authentication, MFA)，无密码认证 (password-less authentication))
  - 四个关键的访问控制服务：身份识别 (身份断言)、认证 (身份验证)、授权 (访问定义)、问责制 (行为责任)。
    - 请注意，AAA 与认证、授权和使用计费 (Accounting) 而不是问责制 (Accountability) 的原则相同 (但它们是相同的原则)。
    - 并且请记住，你需要理解的三个认证因素是知识、所有权和特征 (见上文)。
  - 访问控制系统中的两个重要安全元素是授权和问责制。
    - **授权 (Authorization)**：根据已证实的身份，主体被授予对客体的访问权限；为已识别和认证的用户或进程定义的访问级别。
    - **问责制，又称访问控制原则**：正确的身份识别、认证和授权，并进行日志记录和监控；当实施审计时，用户和其他主体可以为其行为负责；通过使用审计来维持对单个主体的问责制；日志记录用户活动，用户可以为其记录的行为负责；这鼓励良好的用户行为和遵守组织的安全策略；另请参见第 2 领域和上文中的定义/解释。
  - **审计 (Auditing)**：跟踪主体并在其访问客体时进行记录，在一个或多个审计日志中创建审计跟踪。
  - 审计提供问责制。
  - **单因素认证 (Single-factor authentication)**：仅使用一种身份证明的任何认证。
  - **双因素认证 (Two-factor authentication, 2FA)**：需要两种不同的身份证明。
  - **多因素认证 (Multifactor authentication, MFA)**：使用两个或多个因素的任何认证。
    - 多因素认证必须使用多种类型或因素，例如你知道什么和你拥有什么。
    - 注意：要求用户输入密码和 PIN 不是多因素认证 (两者都是你知道什么)。
  - 双因素方法：
    - **基于哈希的消息认证码 (Hash Message Authentication Code, HMAC)**：包括由基于 HMAC 的一次性密码 (HMAC-based One-Time Password, HOTP) 标准用于创建一次性密码的哈希函数。
    - **基于时间的一次性密码 (Time-based One-Time Password, TOTP)**：类似于 HOTP (HMAC-based One-Time Password)，但使用时间戳并在特定时间范围内保持有效 (例如 30 或 60 秒)。
      - 例如，基于电话的认证器应用程序，其中你的手机模仿硬件 TOTP 令牌 (与用户 ID/密码结合使用被认为是双因素或两步认证)。
    - **电子邮件挑战**：一种流行的方法，被网站使用，向用户发送带有 PIN 的电子邮件。
    - 短信服务 (Short Message Service, SMS)：向用户发送带有 PIN 的文本是另一种双因素方法；请注意，NIST SP 800-63B 指出了漏洞，并弃用了将 SMS 作为联邦机构的双因素方法。
  - **无密码认证 (Password-less authentication)**：一种在不要求用户输入密码的情况下验证用户身份的方法；使用备用验证形式，如生物识别、安全令牌或移动设备。
    - 这是一个重要的话题，因为密码的使用 (和滥用) 带来了许多安全难题和问题。
    - 无密码认证的优点包括：
      - 提高安全性
      - 改善用户便利性
      - 降低网络钓鱼风险：如果攻击者获得了密码，但无密码认证使得攻击者访问相关设备变得更加困难 (例如，如果无密码认证通过移动设备)。
    - 无密码认证的缺点：
      - 对设备的依赖 (例如，如果通过手机，则需要该设备才能访问)
      - 与可靠性和隐私相关的生物识别问题
      - 与额外硬件设备等相关的实施成本。

- 5.2.3 会话管理
  - **会话管理 (Session management)**：管理由成功的用户身份识别、认证和授权过程创建的会话；会话管理有助于通过关闭无人值守的会话来防止未经授权的访问；开发人员通常使用 Web 框架来实现会话管理，允许开发人员确保会话在一段时间不活动后关闭。
  - 会话管理对于任何类型的认证系统都非常重要，以防止未经授权的访问。
  - 会话终止策略：
    - 时间表限制：设置系统可用的时间。
    - 登录限制：防止使用相同的用户 ID 同时登录。
    - 超时：会话在一段时间不活动后过期。
    - 屏幕保护程序：在一段时间不活动后激活，需要重新认证。
  - 会话终止和重新认证有助于防止或减轻会话劫持。
  - 开放 Web 应用程序安全项目 (Open Web Application Security Project, OWASP) 发布了"备忘单"，为应用程序开发人员提供了具体的建议。

- 5.2.4 注册、验证和身份建立
  - 在组织内部，新员工在招聘过程中用适当的文件证明自己的身份。
    - 亲自身份验证包括护照、驾照、出生证明等。
  - 在线组织通常使用**基于知识的认证 (knowledge-based authentication, KBA)** 对新人进行身份验证 (例如，新客户创建新的银行/储蓄账户)。
    - 示例问题包括过去的购车记录、抵押贷款支付金额、以前的地址、驾照号码。
    - 然后他们查询权威信息 (例如，征信机构或政府机构) 进行匹配。
  - **认知密码 (Cognitive Passwords)**：在创建账户时收集的安全问题，稍后用作认证问题 (例如，宠物的名字、第一辆车的颜色等)。
    - 与认知密码相关的一个缺陷是，这些信息通常可以在社交媒体网站或一般的互联网搜索中找到。

- 5.2.5 联合身份管理 (Federated Identity Management, FIM)
  - 联合身份管理 (Federated Identity Management, FIM) 系统 (一种 SSO (Single Sign-On) 形式) 通常被基于云的应用程序使用。
  - 联合身份将用户在一个系统中的身份与多个身份管理系统链接起来。
  - FIM 允许多个组织加入一个联盟或团体，同意共享身份信息。
    - 每个组织中的用户可以在自己的组织中登录一次，他们的凭据与联合身份相匹配。
    - 然后用户可以使用此联合身份访问组内任何其他组织的资源。
    - 每个组织决定共享哪些资源。
  - 用于实施联合身份管理系统的方法包括：
    - 安全断言标记语言 (Security Assertion Markup Language, SAML)
    - OAuth (Open Authorization)
    - OpenID Connect (OIDC)
  - 基于云的联合通常使用第三方服务来共享联合身份。
  - 联合身份管理系统可以部署在本地、云中，或作为混合系统两者结合。

- 5.2.6 凭证管理系统 (Credential management systems) (例如，密码保险库)
  - **凭证管理系统 (Credential management systems)**：为用户名和密码提供存储空间。
    - 这些系统帮助开发人员轻松存储用户名/密码，并在用户再次访问网站时检索它们，允许用户自动登录网站而无需再次输入凭据。
  - 万维网联盟 (World Wide Web Consortium, W3C) 于 2019 年 1 月发布了凭证管理级别 1 API 作为工作草案，许多浏览器已经采用。
  - 一些联合身份管理解决方案使用凭证管理 API，允许 Web 应用程序使用联合身份提供程序实现 SSO。
    - 例如，使用你的 Google 或 Facebook 帐户登录 Zoom。
  - **密码保险库 (Password vault) (又称密码管理器 (password manager))**：用于存储和管理凭据的系统；凭据通常保存在由主密码或密钥保护的加密数据库中。
    - 在现代生活中，我们需要访问许多不同的系统，并且在许多系统上重复使用一个 (甚至几个) 密码意味着，如果攻击者推断出你的密码，他们就可以访问许多系统 (以及你的大部分数据)。
    - 密码管理器使得为每个系统创建强大且不同的密码变得更加容易，而无需记住它们。
    - 当然，缺点是如果你的主密码被泄露，攻击者将可以访问你所有的系统。

- 5.2.7 单点登录 (Single Sign-On, SSO)
  - **单点登录 (Single Sign-On, SSO)**：一种集中式访问控制技术，允许主体在系统上一次性认证，并访问多个资源而无需再次认证。
  - 使用 SSO 的优点包括：
    - 减少用户需要记住的密码数量，他们不太可能写下来。
    - 通过减少帐户数量来简化管理。
  - 缺点：
    - 一旦帐户被泄露，攻击者就可以无限制地访问所有授权资源。
  - 在组织内部，通常使用中央访问控制系统 (例如目录服务) 来实现 SSO。
    - **目录服务 (directory service)**：一个集中式数据库，包含有关主体和客体的信息，包括认证数据。
    - 许多目录服务基于轻量级目录访问协议 (Lightweight Directory Access Protocol, LDAP)。

- 5.2.8 即时 (Just-In-Time, JIT)
  - 支持即时 (Just-In-Time, JIT) 配置的联合身份解决方案会自动创建两个实体之间的关系，以便新用户可以访问资源。
  - JIT 配置在用户首次登录网站时在第三方网站上创建用户帐户；JIT 减少了管理工作量。
  - JIT 解决方案在没有任何管理干预的情况下创建连接。
  - JIT 系统通常使用 SAML (Security Assertion Markup Language) 来交换所需的数据。

## [5.3](#53-federated-identity-with-a-third-party-service-osg-10-chpt-13) 与第三方服务联合身份 (OSG-10 第 13 章)

- 5.3.1 本地
  - 联合身份管理可以部署在本地，通常为组织提供最大的控制权。

- 5.3.2 云
  - 基于云的应用程序使用联合身份管理 (Federated Identity Management, FIM) 系统，这是一种 SSO (Single Sign-On) 的形式。
  - 基于云的联合通常使用第三方服务来共享联合身份 (例如，培训网站使用联合 SSO 系统)，通常将用户的内部登录 ID 与联合身份进行匹配。

- 5.3.3 混合
  - 混合联合是基于云的解决方案和本地解决方案的组合。

## [5.4](#54-implement-and-manage-authorization-mechanisms-osg-10-chpt-14) 实施和管理授权机制 (OSG-10 第 14 章)

- 授权确保所请求的活动或客体访问是可能的，考虑到经过认证的身份的权限。
  - 例如，确保具有适当权限的用户可以访问资源。
  - 常见的授权机制包括：
    - 隐式拒绝
    - 访问控制列表
    - 访问控制矩阵
    - 能力表
    - 受限接口
    - 内容相关控制
    - 上下文相关控制

- 5.4.1 基于角色的访问控制 (Role-Based Access Control, RBAC)
  - **基于角色的访问控制 (Role-Based Access Control, RBAC)**：关键特征是使用角色或组；RBAC 模型使用基于任务的角色，当管理员将其帐户放入角色或组时，用户获得权限；将用户从角色中移除会移除通过角色成员资格授予的权限。
  - 不是直接向用户分配权限，而是将用户帐户放入角色中，管理员向角色分配权限 (通常由工作职能定义)。
    - 如果用户帐户在角色中，则用户拥有分配给该角色的所有权限。
  - MS Windows 操作系统使用此模型与组。
  - RBAC 模型可以根据组织的层次结构将用户分组到角色中，它是一种非自由裁量访问控制模型；中央权威访问决策可以使用 RBAC 模型。
  - RBAC 允许以最小的管理开销为用户分配权限。

- 5.4.2 基于规则的访问控制
  - **基于规则的访问控制 (Rule-based Access Control)**：使用一组规则、限制或过滤器来确定访问；关键特征是它将全局规则应用于所有主体。
    - 例如，防火墙访问控制列表使用规则列表来定义允许哪些访问和阻止哪些访问。
  - 基于规则的访问控制模型中的规则有时被称为限制或过滤器。

- 5.4.3 强制访问控制 (Mandatory Access Control, MAC)
  - **强制访问控制 (Mandatory Access Control, MAC)**：要求系统本身根据组织的安全策略管理访问控制的访问控制。
  - MAC 模型的关键特征是使用应用于主体和客体的标签；主体需要匹配的标签才能访问客体。
    - 例如，最高机密的标签授予对最高机密文档的访问权限。
  - 当以表格形式记录时，MAC 模型有时类似于一个格子 (即攀缘玫瑰丛框架)，因此它被称为基于格子的模型。
  - MAC 模型强制执行"需要知道"原则，并支持分层环境、分区环境或两者的组合 (混合环境)。

- 5.4.4 自由裁量访问控制 (Discretionary Access Control, DAC)
  - **自由裁量访问控制 (Discretionary Access Control, DAC)**：资产或系统所有者决定谁获得访问权限的访问控制模型。
  - DAC 模型的关键特征是每个客体都有一个所有者，所有者可以授予或拒绝任何其他主体的访问权限。
    - 例如，你创建一个文件并且是所有者，你可以授予该文件的权限。
  - 所有客体都有所有者，所有者可以修改权限。
  - 每个客体都有一个访问控制列表，定义了权限 (例如，读取和修改文件)。
  - 所有其他模型都是非自由裁量模型，管理员集中管理非自由裁量控制。
  - Windows 中使用的新技术文件系统 (New Technology File System, NTFS) 使用 DAC (Discretionary Access Control) 模型。
  - **非自由裁量访问控制 (Non-discretionary Access Control)**：资产所有者以外的某人确定访问权限。

- 5.4.5 基于属性的访问控制 (Attribute-Based Access Control, ABAC)
  - **基于属性的访问控制 (Attribute-Based Access Control, ABAC)**：基于规则的访问模型的高级实现，根据属性应用规则；一种访问控制范例，其中访问权限通过将属性组合在一起的策略授予用户。
  - ABAC 模型的关键特征是其使用规则，这些规则可以包括有关用户、环境、用户操作和目标资源的多个属性。
    - 这使其比将规则平等地应用于所有主体的基于规则的访问控制模型更加灵活。
    - 许多软件定义网络 (Software-Defined Networks, SDN) 使用 ABAC (Attribute-Based Access Control) 模型。
  - ABAC 允许管理员使用简单的语言语句在策略中创建规则，例如"允许经理使用移动设备访问广域网"。
  - ABAC 使用 XACML (eXtensible Access Control Markup Language)，它定义了基于属性的访问控制策略语言、体系结构和处理模型。

- 5.4.6 基于风险的访问控制
  - **基于风险的访问控制 (Risk-based access control)**：评估环境和情况，并根据软件安全策略做出决策。
    - 一种在评估风险后授予访问权限的模型；它可以根据多个因素控制访问，例如由 IP 地址确定的用户位置、用户是否使用 MFA (Multi-Factor Authentication) 登录以及用户的设备。
    - 高级模型使用机器学习，根据过去的活动对当前活动做出预测性结论。
    - 请注意，基于风险的访问控制可以用来 (例如) 通过评估环境和情况并使用该信息来阻止被视为异常的流量，从而阻止来自受感染物联网 (Internet of Things, IoT) 设备的恶意流量。

- 5.4.7 访问策略执行 (Access policy enforcement) (例如，策略决策点 (policy decision point)、策略执行点 (policy enforcement point))
  - **访问策略执行 (Access policy enforcement)**：在组织内执行访问控制策略以规范和管理访问。
  - 策略决策点 (Policy Decision Point, PDP)：负责根据预定义的访问策略和规则做出访问控制决策的系统；PDP 评估访问请求。
  - 策略执行点 (Policy Enforcement Point, PEP)：负责执行由 PDP (Policy Decision Point) 做出的访问控制决策；PEP 充当网守。

## [5.5](#55-manage-the-identity-and-access-provisioning-lifecycle-osg-10-chpts-1314) 管理身份和访问配置生命周期 (OSG-10 第 13、14 章)

- 5.5.1 帐户访问审查 (例如，用户、系统、服务)
  - 管理员需要定期审查用户、系统和服务帐户，以确保它们符合安全策略并且没有过多的权限。
  - 谨慎使用本地系统帐户作为应用程序服务帐户；虽然它允许应用程序在不创建特殊服务帐户的情况下运行，但它通常授予应用程序超出其需要的访问权限。
  - 你可以使用脚本定期运行并检查未使用的帐户，并检查特权组成员身份，删除未经授权的帐户。
  - 防范两个访问控制问题：
    - 过度权限：当用户拥有的权限超过其分配的工作任务所规定时发生；这些权限应被撤销。
    - 权限蔓延 (creeping privileges) (又称权限蠕变 (privilege creep))：随着工作角色和分配任务的改变，用户帐户随着时间的推移累积额外的权限。

- 5.5.2 配置和停用 (例如，入职/离职和调动)
  - 身份和访问配置生命周期指帐户的创建、管理和删除。
    - 这个生命周期很重要，因为没有正确定义和维护的用户帐户，系统就无法建立准确的身份、执行认证、提供授权和跟踪问责制。
  - 配置/入职
    - 配置确保帐户根据任务要求具有适当的权限，并且员工收到所需的硬件；换句话- 说，包括从应用程序、系统和目录中创建、维护和删除用户对象。
    - 正确的用户帐户创建或配置，确保人员在创建帐户时遵循特定的程序。
      - 新用户帐户创建又称注册或登记。
    - **自动配置 (Automatic provisioning)**：向应用程序提供信息，然后应用程序通过预定义的规则创建帐户 (根据角色分配到适当的组)。
      - 自动配置系统始终如一地创建帐户。
    - **工作流配置 (Workflow configuration)**：通过已建立的工作流 (如人力资源流程) 进行的配置。
    - 配置还包括向员工发放硬件、令牌、智能卡等。
    - 向员工发放硬件时，保持准确的记录非常重要。
    - 配置后，组织可以跟进入职流程，包括：
      - 员工阅读并签署可接受使用策略 (acceptable use policy, AUP)
      - 解释安全最佳实践 (如受感染的电子邮件)
      - 审查移动设备策略
      - 确保员工的计算机可以运行，并且他们可以登录
      - 配置密码管理器
      - 解释如何联系帮助台
      - 展示如何访问、共享和保存资源
  - 停用/离职
    - 停用流程在员工离职时禁用或删除帐户，离职流程确保员工归还组织发给他们的所有硬件。
    - 当员工离开组织或调到不同部门时，会发生停用/离职。
    - **帐户撤销 (Account revocation)**：删除帐户是停用的最简单方法。
      - 员工的帐户通常首先被禁用。
      - 然后主管可以审查用户的数据并确定是否需要任何东西。
      - 注意：如果被解雇的员工在离职面谈后仍然可以访问用户帐户，那么破坏的风险非常高。
    - 停用包括收集发给员工的任何硬件，例如笔记本电脑、移动设备和认证令牌。

- 5.5.3 角色定义和转换 (例如，分配到新角色的人员)
  - 当创建新的工作角色时，识别该角色中的某人所需的权限非常重要；这确保了新角色中的员工没有过多的权限。
  - 员工的职责可以以调到不同角色或新创建角色的形式改变。
    - 对于新角色，定义角色和该角色中员工所需的权限非常重要。
  - 角色和相关组需要根据权限进行定义。

- 5.5.4 权限提升 (例如，使用 sudo，审计其使用)
  - **权限提升 (Privilege escalation)**：指任何给予用户超出其应有权限的情况。
  - 攻击者在利用单个系统后，使用权限提升技术来获得提升的权限；通常，他们首先尝试在被利用的系统上获得额外的权限。
  - **水平权限提升 (Horizontal privilege escalation)**：给予攻击者与第一个被攻陷用户相似的权限，但来自其他帐户。
  - **垂直权限提升 (Vertical privilege escalation)**：为攻击者提供明显更大的权限。
    - 例如，在攻陷普通用户帐户后，攻击者可以使用垂直权限提升技术来获得用户计算机上的管理员权限。
    - 然后攻击者可以使用水平权限提升技术来访问网络中的其他计算机。
    - 这种在整个网络中的水平权限提升又称**横向移动 (lateral movement)**。
  - 限制给予服务帐户的权限可以降低某些权限提升攻击的成功率；这应包括尽量减少 sudo 帐户的使用。

- 5.5.5 服务帐户管理
  - **服务帐户 (Service account)**：由应用程序、服务、系统用于与其他资源、服务或数据库交互，无需人工干预。
    - 尽管这些帐户主要不是由人类用于认证，但这并不意味着它们可以被忽略；需要审查和管理这些帐户及其安全性。
  - **服务帐户管理 (Service account management)**：创建、配置、监控和维护服务帐户的过程。
    - 确保服务帐户安全，降低未经授权访问或滥用的风险。

## [5.6](#56-implement-authentication-systems-osg-10-chpt-14) 实施认证系统 (OSG-10 第 14 章)

- **联合身份管理 (Federated Identity Management, FIM)**：(又称联合访问 (federated access)) 一次性认证以获得对多个系统的访问权限，包括与其他组织相关的系统；FIM 系统将一个系统中的用户身份与其他系统链接起来以实现 SSO；FIM 系统部署在本地 (提供最大的控制权)、通过第三方云服务或作为混合系统；使用你的 Microsoft 帐户向第三方 SaaS (Software as a Service) 进行认证是 FIM 的一个例子。
  - FIM 信任关系包括：主体/用户、身份提供者 (拥有身份并执行认证的实体) 和依赖方 (又称服务提供者)。
  - FIM 协议包括 SAML (Security Assertion Markup Language)、WS-Federation、OpenID (认证) 和 OAuth (Open Authorization) (授权)。
  - 比较 FIM 和 SSO：用户使用 SSO 一次性认证以访问一个组织中的多个系统；用户使用 FIM 一次性认证以访问一个组织内外多个系统，因为存在多实体信任关系。
- XML 在第 8 领域中定义，但本质上可扩展标记语言 (Extensible Markup Language, XML) 是一组 HTML (HyperText Markup Language) 扩展，用于在网络环境中进行数据存储和传输；常用于将网页与数据库集成；XML 通常嵌入到构成网页元素的 HTML 文件中。
  - XML 不仅仅描述如何显示数据，它还使用标签描述数据本身。
- 安全断言标记语言 (Security Assertion Markup Language, SAML)
  - **安全断言标记语言 (Security Assertion Markup Language, SAML)**：一种开放的基于 XML (eXtensible Markup Language) 的标准，通常用于在联合组织之间交换认证和授权 (authentication and authorization, AA) 信息。
  - 常用于集成云服务，并提供进行认证和授权断言的能力。
  - SAML (Security Assertion Markup Language) 为浏览器访问提供 SSO (Single Sign-On) 功能。
  - 结构化信息标准促进组织 (Organization for the Advancement of Structure Information Standards, OASIS) 维护它。
  - SAML 2.0 是一个开放的基于 XML (eXtensible Markup Language) 的标准。
  - SAML 2.0 规范使用三个实体：
    - **主体或用户代理 (Subject or User Agent)**：主体是试图使用该服务的用户。
    - **服务提供商 (Service Provider, SP) (或依赖方 (relying party))**：为用户提供服务。
    - **身份提供商 (Identity Provider, IdP)**：持有用户认证和授权信息的第三方。
  - IdP (Identity Provider) 可以发送三种类型的 XML (eXtensible Markup Language) 消息，称为断言：
    - **认证断言 (Authentication Assertion)**：提供用户代理提供了正确凭据的证明，识别身份识别方法，并识别用户代理登录的时间。
    - **授权断言 (Authorization Assertion)**：指示用户代理是否有权访问所请求的服务；如果被拒绝，则包括原因。
    - **属性断言 (Attribute Assertion)**：属性可以是有关用户代理的任何信息。
- OpenID Connect (OIDC) / 开放授权 (Open Authorization, OAuth)
  - **OpenID 提供认证**
  - **OpenID Connect (OIDC)**：一个使用 OAuth 2.0 授权框架的认证层，由 OpenID 基金会维护 (不是 IETF (Internet Engineering Task Force))；OIDC (OpenID Connect) 提供认证和授权 (通过使用 OAuth (Open Authorization) 框架)。
    - OIDC (OpenID Connect) 是一个基于 RESTful、JSON (JavaScript Object Notation) 的认证协议，与 OAuth (Open Authorization) 配对时可以提供身份验证和基本配置文件信息；使用 JSON Web 令牌 (JSON Web Tokens, JWT)，(又称 ID 令牌 (ID token))。
  - OAuth (Open Authorization) 和 OIDC (OpenID Connect) 与许多基于 Web 的应用程序一起使用，以共享信息而无需共享凭据。
    - OAuth (Open Authorization) 提供授权。
    - OIDC (OpenID Connect) 使用 OAuth (Open Authorization) 框架进行授权，并建立在 OpenID 技术之上进行认证。
  - **OAuth 2.0**：一个开放的授权框架，在 RFC 6749 中描述 (由互联网工程任务组 (Internet Engineering Task Force, IETF) 维护)。
    - OAuth (Open Authorization) 通过 API (Application Programming Interfaces) 交换数据。
    - OAuth (Open Authorization) 是用于云服务授权和权利委托的最广泛使用的开放标准。
    - 基于 OAuth (Open Authorization) 构建的最常见协议是 OpenID Connect (OIDC)；OpenID 用于认证。
    - OAuth 2.0 使第三方应用程序能够获得对 HTTP (Hypertext Transfer Protocol) 服务的有限访问权限，无论是代表资源所有者 (通过协调批准交互)，还是允许第三方应用程序代表自己获得访问权限；OAuth 提供了从另一个服务访问资源的能力。
    - OAuth 2.0 通常用于对应用程序的委托访问，例如，一个自动从社交媒体应用程序中找到你的新朋友的手机游戏可能正在使用 OAuth 2.0。
  - 相反，如果你使用社交媒体帐户登录一个新的手机游戏 (而不是仅为该游戏创建一个用户帐户)，该过程可能会使用 OIDC。
- Kerberos
  - **Kerberos 是组织内最常用的 SSO 方法**
  - **Kerberos 的主要目的是认证**
  - **Kerberos 使用对称加密和票据来证明身份并提供认证**
  - **Kerberos 依赖 NTP (Network Time Protocol) 来同步服务器和客户端之间的时间**
  - **Kerberos 使用端口 88 进行认证通信**，客户端通过该端口与 KDC 服务器通信，以便用户可以有效地访问特权网络资源。
  - Kerberos 是一种网络认证协议，广泛用于公司和专用网络，并存在于许多 LDAP (Lightweight Directory Access Protocol) 和目录服务解决方案中，例如 Microsoft Active Directory。
  - 它提供单点登录，并使用加密来加强认证过程并保护登录凭据。
  - 票据认证是一种采用第三方实体来证明身份并提供认证的机制 - Kerberos 是一个众所周知的票据系统。
  - 在用户认证并证明其身份后，Kerberos 使用其已证实的身份来颁发票据，用户帐户在访问资源时出示这些票据。
  - Kerberos 版本 5 依赖于对称密钥加密 (又称秘密密钥加密)，使用高级加密标准 (Advanced Encryption Standard, AES) 对称加密协议。
  - Kerberos 为认证流量提供机密性和完整性，使用端到端安全，并有助于防止窃听和重放攻击。
  - Kerberos 默认使用 UDP (User Datagram Protocol) 端口 88。
  - Kerberos 元素：
    - **密钥分发中心 (Key Distribution Center, KDC)**：提供认证服务的受信任第三方。
    - **Kerberos 认证服务器**：托管 KDC 的功能：
      - **票据授予服务 (Ticket-Granting Service, TGS)**：提供主体已通过 KDC (Key Distribution Center) 认证并有权请求访问其他客体的票据的证明。
        - 用于完整票据授予服务的票据称为票据授予票据 ([TGT](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets))；当客户端向 KDC (Key Distribution Center) 请求服务器票据时，它以认证器消息和票据 (TGT) 的形式出示凭据，票据授予服务用其主密钥打开 TGT，提取此客户端的登录会话密钥，并使用登录会话密钥加密客户端的服务器会话密钥副本。
        - TGT (Ticket-Granting Ticket) 被加密并包括对称密钥、过期时间和用户的 IP (Internet Protocol) 地址。
        - 主体在请求访问客体的票据时出示 TGT。
      - **认证服务 (Authentication Service, AS)**：验证或拒绝票据的真实性和及时性；通常称为 KDC (Key Distribution Center)。
    - **票据 (Ticket) (又称服务票据 (service ticket, ST))**：一种加密消息，提供主体有权访问客体的证明。
    - **Kerberos 主体**：通常是用户，但可以是任何可以请求票据的实体。
    - **Kerberos 领域**：由 Kerberos 统治的逻辑区域 (例如域或网络)。
  - Kerberos 登录过程：
    1) 用户提供认证凭据 (在客户端中键入用户名/密码)。
    2) 生成客户端/TGS 密钥。
        - 客户端使用 AES (Advanced Encryption Standard) 加密用户名以传输到 KDC。
        - KDC 根据已知凭据数据库验证用户名。
        - KDC 生成将由客户端和 Kerberos 服务器使用的对称密钥。
        - 它用用户密码的哈希值加密此密钥。
    3) 生成 TGT - KDC (Key Distribution Center) 生成加密的时间戳 TGT。
    4) 生成客户端/服务器票据。
        - 然后 KDC (Key Distribution Center) 将加密的对称密钥和加密的时间戳 TGT (Ticket-Granting Ticket) 传输到客户端。
        - 客户端安装 TGT 以供使用，直到它过期。
        - 客户端还使用用户密码的哈希值解密对称密钥。
        - 注意：客户端的密码永远不会在网络上传输，但它会被验证。
            - 服务器使用用户密码的哈希值加密对称密钥，并且只能用用户密码的哈希值解密。
    5) 用户访问所请求的服务。
  - 当客户端想要访问客体 (如托管资源) 时，它必须通过 Kerberos 服务器请求票据，步骤如下：
    - 客户端将其 TGT (Ticket-Granting Ticket) 连同访问资源的请求一起发送回 KDC (Key Distribution Center)。
    - KDC (Key Distribution Center) 验证 TGT (Ticket-Granting Ticket) 是否有效，并检查其访问控制矩阵以验证用户对所请求资源的权限。
    - KDC 生成服务票据并将其发送给客户端。
    - 客户端将票据发送到托管资源的服务器或服务。
    - 托管资源的服务器或服务与 KDC 验证票据的有效性。
    - 一旦身份和授权得到验证，Kerberos 活动就完成了。
      - 然后服务器或服务主机与客户端打开会话并开始通信或数据传输。
- 远程认证拨入用户服务 (Remote Authentication Dial-in User Service, RADIUS) / 终端访问控制器访问控制系统增强版 (Terminal Access Controller Access Control System Plus, TACACS+)
  - 有几种协议提供集中的认证、授权和计费服务；网络 (或远程) 访问系统使用 AAA 协议。
  - **远程认证拨入用户服务 (Remote Authentication Dial-in User Service, RADIUS)**：集中管理远程访问连接 (如 VPN (Virtual Private Network) 或拨号访问) 的认证。
    - 用户可以连接到任何网络访问服务器，然后该服务器将用户的凭据传递给 RADIUS 服务器以验证认证和授权并跟踪计费。
    - 在此上下文中，网络访问服务器是 RADIUS 客户端，RADIUS 服务器充当认证服务器。
    - RADIUS 服务器还为多个远程访问服务器提供 AAA 服务。
    - RADIUS (Remote Authentication Dial-in User Service) 默认使用用户数据报协议 (User Datagram Protocol, UDP)，并且只加密密码交换。
    - RFC 6614 定义了使用传输层安全 (Transport Layer Security, TLS) 的 RADIUS over TCP (Transmission Control Protocol) (端口 2083)。
    - RADIUS (Remote Authentication Dial-in User Service) 使用 UDP (User Datagram Protocol) 端口 1812 进行 RADIUS 消息，使用 UDP (User Datagram Protocol) 端口 1813 进行 RADIUS 计费消息。
    - RADIUS 默认只加密密码交换。
    - 可以使用 RADIUS/TLS 加密整个会话。
  - 思科开发了**终端访问控制访问控制系统增强版 (Terminal Access Control Access Control System Plus, TACACS+)** 并将其作为开放标准发布。
    - 提供了对早期版本和 RADIUS 的改进，它将认证、授权和计费分离为可以托管在三个不同服务器上的独立过程。
    - 此外，TACACS+ 加密所有认证信息，而不仅仅是密码，就像 RADIUS 所做的那样。
    - TACACS+ 使用 TCP (Transmission Control Protocol) 端口 49，为数据包传输提供了更高的可靠性。
  - **Diameter AAA 协议**：一种先进的系统，旨在解决旧 RADIUS (Remote Authentication Dial-in User Service) 协议的局限性 (直径是半径的两倍！)；Diameter 通过提供增强的安全性 (使用 IPsec (Internet Protocol Security) 或 TLS (Transport Layer Security) 而不是 MD5 (Message Digest 5) 哈希)、支持更广泛的属性集 (适用于大型、复杂的网络) 并能处理复杂的会话来改进 RADIUS。
    - Diameter 基于 RADIUS，并改进了其许多弱点，但 Diameter 与 RADIUS 不兼容。 