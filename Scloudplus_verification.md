# Scloud+ 下载版拒绝采样报告独立核验

核验日期：2026-09-29。对象是用户当天新下载的实现，而非仅依据原文或旧目录。

## 1. 版本来源

- 下载包：`/Users/yu/Downloads/Scloud+.zip`，12,578,761 字节，下载文件时间 2026-09-29 10:51。
- SHA-256：`050aad7293ec90fafd9070e82877eedc81caf0aaaca932c995619a3f35429876`。
- 解压位置：本目录的 `latest-download/`。
- 实现根目录：`latest-download/Implementations and Test_Vectors/Implementations/`。
- 将其与先前的 `/Users/yu/workspace/niccs_round1/kem/code/Scloud+/Implementations and Test_Vectors/Implementations/` 做 `diff -qr`，退出码 0，无差异。比较覆盖整份实现目录。

这只能确认与用户此次下载包一致，不能仅凭本地文件时间判断是否是发布方目前的最新版。

## 2. 核心结论

**256/384/512 的 FO 重加密确实包含由恢复明文及公钥决定的、非固定次数的拒绝采样工作。128/192 的这项采样工作量固定。**

这项源代码问题得到原始 C 实现的计数验证，并在 256 档真实解封装中获得两个不同 XOF 生成量的见证。本文没有测量时间，不能据此确认可观测 PCO、远程攻击、密钥恢复或攻击查询复杂度。128/192 不受这项拒绝采样问题影响，不代表它们的整个实现没有其他侧信道。

原文的核心调用链正确，但定量表、线性时序模型、信息量上界和部分 prior art 表述需要修正。

## 3. 最新源码证据

以下路径相对于实现根目录的 `_shared/scloudplus_core/`：

| 位置 | 行为 |
|---|---|
| `common/kem.c:96` | 实际函数名是 `scloud_kemdecaps` |
| `common/kem.c:103` | `pke_dec` 恢复明文 |
| `common/kem.c:104` | 拼接密钥中保存的 `H(pk)` |
| `common/kem.c:106` | `G(m || H(pk))` 生成重加密硬币 |
| `common/kem.c:107` | 调用 `pke_enc` |
| `common/kem.c:108` | 重加密完成后才验证密文 |
| `common/pke.c:108` | `F` 将硬币扩展为两条采样流的种子 |
| `common/pke.c:110` | `sample_sp` 采样 S' |
| `common/pke.c:111` | `sample_e12` 用同一条流采样 E1/E2 |
| `common/sample.c:325` | BD6 每批读取 96 字节，处理 256 个候选 |
| `common/sample.c:358` | 3-bit 候选，接受 `<6`；每系数需要两个 accepted bits |
| `common/sample.c:401` | BD12 每批读取 128 字节，处理 256 个候选 |
| `common/sample.c:428` | 4-bit 候选，接受 `<12`；每系数需要两个 accepted bits |
| `common/sample.c:93` | SHAKE 采样 reader 每次生成 4 个块；BD6/BD12 即 544 字节 |

BD6/BD12 的拒绝率均为 1/4。全批拒绝概率 `(1/4)^256` 在均匀独立候选模型下极小；主要变动来自凑够固定数量 accepted bits 所需的批数。无效密文不会跳过该过程。

## 4. 原始 C 实现运行证据

环境：macOS ARM64，Apple clang，`-O2 -std=c99`，SHAKE family。

`verify_sampler.c` 直接包含原始 `sample.c`，包装其 SHAKE squeeze 调用计数，并读取 reader 最终位置。它用真实 H/G/F 生成种子，逐数组 `memcmp` 检查被检查的 reader 调用与原始公开 `sample_sp/sample_e12` API 一致。

五档各取 512 个明文：前 8 字节为小端计数器，其余为零；公钥序列化字节全零。这组公钥字节仅用于确定性的采样实验，不作为合法密钥声明。分别原生编译 ref、NEON，计数与系数 FNV 摘要全部一致，并检查前 8 个明文跨进程重放。摘要比较不是全输入逐字节等价性的证明；AVX2 仅做源码核对，没有在本机执行。

下表是这 512 个确定性输入的观测范围和样本均值，不是全明文域的精确分布，也不是时序测量：

| 档 | 采样器读取字节范围 | 读取均值 | 读取标准差 | 采样 XOF 生成字节范围 |
|---|---:|---:|---:|---:|
| 128 | 3,664 | 3,664.00 | 0 | 4,032 |
| 192 | 5,025 | 5,025.00 | 0 | 5,376 |
| 256 | 28,416–28,896 | 28,644.75 | 74.58 | 28,832–29,376 |
| 384 | 53,376–53,856 | 53,600.25 | 92.00 | 53,856–54,400 |
| 512 | 102,400–103,168 | 102,869.75 | 135.44 | 102,816–103,904 |

另用原始 `scloud_kemkeygen` 生成一把合法 256 档密钥，搜索 2,048 个明文。构造 `C1=0, C2=Pack10(msg_encode(m))` 的密文，检查恢复明文、FO 重加密密文不匹配，然后实际执行两次 `scloud_kemdecaps`。

本次端到端运行的见证：

- 明文计数器 0：两次实际解封装均产生 29,376 字节采样 XOF 输出。
- 明文计数器 163：两次实际解封装均产生 28,832 字节采样 XOF 输出。
- 两个见证均通过恢复明文检查、重加密不匹配检查、预测生成量检查和共享密钥重放检查。

该探针的明文由攻击者直接指定，与私钥无关。它只验证无效密文路径仍执行消息相关采样，没有完成私钥相关探针或攻击。每次复跑生成新密钥，出现差异的明文计数器可能改变。

## 5. 原文必须修正的定量论断

### 5.1 三种字节口径不可混用

对两个采样流 j∈{s,e}，令 `K_j` 为得到 `2*N_j` 个 accepted bits 所需的候选数。均匀独立候选模型下可用负二项分布描述它。

```text
理想候选位成本：C = bits_per_candidate * (K_s + K_e) / 8
实际采样批数：  R_j = ceil(K_j / 256)
实际读取字节：  L_read = b * (R_s + R_e)
reader 生成量： L_gen = 544 * [ceil(b*R_s/544) + ceil(b*R_e/544)]
b = 96（BD6）或 128（BD12），这里的 544 仅适用于 SHAKE256 采样。
```

原文 256 档的 `E[L]=28,548, sd[L]=59.7` 是理想 C 的矩，不是批读取 `L_read` 或生成量 `L_gen` 的精确矩。两个采样流都存在批尾舍弃及 reader 预生成。若讨论整个重加密的 XOF 总量，还应说明 F 与矩阵扩展等固定长度工作是否计入。

上述分布模型假设 XOF 输出可视为独立均匀随机比特。固定真实哈希函数、公钥及明文集合的精确分布，不能由这个模型自动推出。

### 5.2 线性时间映射没有得到验证

同一个 `R_s+R_e` 也可能对应不同 `L_gen`。在固定全零公钥的 256 档 CSV 中：

| 明文计数器 | R_s | R_e | 总批数 | L_read | L_gen |
|---|---:|---:|---:|---:|---:|
| 238 | 148 | 148 | 296 | 28,416 | 29,376 |
| 455 | 147 | 149 | 296 | 28,416 | 28,832 |

生成量存在 544 字节阶梯。两个流的批数、reader refill 次数、跨缓冲区复制和 accepted-bit 队列访问都可能影响时间。因此“块跨越次数近乎固定，所以 `T=c_total*L+const+noise` 已验证成立”没有证据。近似线性模型可以拟合测试，不能提前宣布成立。

### 5.3 熵与平均测量次数需限定假设

`H(R_total)≈1.62 bit` 仅描述特定分布下理想总批数观测的熵。只有额外建立 `M -> R_total -> T` 的通道假设，它才是该时间通道信息量的上界。实现中相同总批数可对应不同哈希工作；解码及其他访存还可能提供信息，不能宣布整个解封装真实信息量必然小于 1.62 bit。

原文的无限平均与 `sigma/sqrt(N)` 需要稳定密钥、可重放及适当独立/平稳噪声假设。`N>(2*sigma/Delta)^2` 是简化信噪比条件，不包含指定误判率、检验功效和两个样本均值的方差，不能直接推出攻击可行或不可行。

### 5.4 离线可计算性的输入不完整

应写成固定参数、family、公钥后的函数 `L_{level,family,pk}(m)`。已知候选明文和公钥可以算出其工作量；仅给任意公钥及密文，无法无条件知道实际恢复明文或其工作量。非固定工作的源码结构与具体见证也不能自动升级为“对所有公钥”的无条件数学定理。

## 6. Prior Art 核验

1. **已存在公开针对 Scloud+ 的侧信道论文**：[Efficient Key Recovery via Correlation Power Analysis on Scloud⁺](https://eprint.iacr.org/2025/721)，Hangyu Bai、Fan Huang、Xiaolin Duan、Honggang Hu，2025 年。其目标是密文与私钥矩阵乘法的功耗相关分析，涉及不同版本参数。它直接否定原文“没有任何公开 Scloud+ 侧信道分析”，但不能据此认定本文同一拒绝采样时序缺陷已被发表。
2. **HQC/BIKE 类别先例正确**：[Don't Reject This](https://tches.iacr.org/index.php/TCHES/article/view/9700)，TCHES 2022(3)，DOI `10.46586/tches.v2022.i3.223-263`。摘要明确指出确定性重加密中的拒绝采样时序攻击。原文给的 `iacr.org/tches/2022/a12/` 链接无效；HQC 866,000 和 BIKE 5.8×10^7 的理想 oracle 查询量不能迁移为 Scloud+ 的复杂度。距离谱恢复对应 BIKE，不应归给 HQC。
3. **Awan–Rao 的定理被误用**：[Privacy-Aware Rejection Sampling](https://jmlr.org/papers/v24/21-0870.html)，JMLR 24(74)，2023。其“接受概率恒定”指跨数据库相同，讨论具有新鲜采样随机性的 DP 场景。此处 p 固定为 3/4，风险来自由隐藏明文决定的确定性随机流。该定理不能按原文方式证明本问题。
4. [Masked Vector Sampling for HQC](https://eprint.iacr.org/2024/1106) 的摘要支持 HQC 在时序攻击后更新常数时间采样器这一处置先例。

当前核验没有找到公开指认同一 Scloud+ FO/BD6/BD12 时序问题的文献。这是检索结果，不能作为新颖性证明。

## 7. 修复与 finding 定性

建议将 finding 写成“FO 重加密中的确定性拒绝采样引入消息相关工作量”。源代码及计数层面已确认；可观测时序 oracle、密钥恢复、远程可行性和最终严重度仍待验证。

修复不能只写“固定 XOF 字节预算并掩码合并”。必须同时处理压缩写入地址/访问、接受数不足的情况、剩余概率及精确或近似分布。BD6/BD12 的单个 accepted bit 分别为 Bernoulli(1/6)、Bernoulli(1/12)，有限个固定均匀随机比特不能精确实现这种非二进制分母概率。

换成 BD2/BD4 会改变噪声分布，需重新评估安全参数和 DFR，不能作为无条件替换补丁。256 字节缓冲区也不足以证明数据相关访问的缓存泄漏可忽略。

## 8. 复跑与覆盖边界

```sh
python3 verify_report.py \
  --implementations 'latest-download/Implementations and Test_Vectors/Implementations' \
  --trials 512 --output-dir latest-verification --full-kem
```

产物：`latest-verification/verification-results.json`、五档 ref/NEON CSV、`verify-full-kem-256.csv`、`verify-full-kem-256.log`、`provenance.json`。

已运行：SHAKE family 的原始 ref/NEON 采样器、五档计数、重复输入；256 档原始 ref 全 KEM、合法密钥和无效密文重放。

未运行：AVX2 原生执行、SM3 family、真实时间/周期/功耗测量、TVLA、远程测试、私钥相关探针和密钥恢复。不能把计数实验称为时序攻击实测，也不能把有限测试称为三后端全输入形式等价证明。
