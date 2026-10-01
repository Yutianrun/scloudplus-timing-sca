# First-row C1/C2 probes

在 level-256、SHAKE、参考实现下，固定稀疏
`C1[0,0]=1`，其余 C1 项为零；只设置 `C2[0,0..10]`，其余 C2 项为零。
解码输入满足

```text
D[0,j] = C2[0,j] - s[j] (mod 1024),  s[j] in {-1,0,+1}
```

对每个固定的 `s0=s[0]`，把另外 10 个系数枚举完毕（`3^10=59049`），检查解码结果和采样桶。

## Probe A

```text
C1 step = 1
C2 first row = 256,0,576,512,256,128,192,512,384,896,576
```

| s0 | decoded message | sampler bucket | combinations |
|---:|---|---:|---:|
| -1 | `4c02048005005a090001a095001020510005a095001020510005120550203d08` | 53 | 59049 |
| 0  | `4c02048005005a090001a095001020510005a095001020510005120550203d08` | 53 | 59049 |
| +1 | `0012042001001009520100912015005420020091201500542002400522003a1f` | 54 | 59049 |

## Probe B

只把 `C2[0,0]` 改成 255：

```text
C1 step = 1
C2 first row = 255,0,576,512,256,128,192,512,384,896,576
```

| s0 | decoded message | sampler bucket | combinations |
|---:|---|---:|---:|
| -1 | `4c02048005005a090001a095001020510005a095001020510005120550203d08` | 53 | 59049 |
| 0  | `0012042001001009520100912015005420020091201500542002400522003a1f` | 54 | 59049 |
| +1 | `0012042001001009520100912015005420020091201500542002400522003a1f` | 54 | 59049 |

Thus the pair `(A,B)` gives bucket patterns `(53,53)`, `(53,54)`, `(54,54)` for `s0=-1,0,+1`.

按实际询问顺序，可以把 Probe B 作为第一次询问、Probe A 作为第二次询问。两次只差 `C2[0,0]` 的一个单位：

```text
Probe 1: C2[0,0] = 255  ->  -1 与 {0,+1} 分开
Probe 2: C2[0,0] = 256  ->  {-1,0} 与 +1 分开
```

因此观测对 `(Probe 1, Probe 2)` 为：

```text
s0 = -1 -> (53,53)
s0 =  0 -> (54,53)
s0 = +1 -> (54,54)
```

The row formula and the 177147 candidate records were checked against genuine decryption. Message stability is exhaustive. Raw recursive BDD coordinates can differ by a representation outside the first row for some tail choices, but those differences are zero modulo q and do not change the decoded message; the modulo-q check passed for all candidates. The saved public-key hash is `a9eb16cb51e75e1b7ddc6a7559f30d467ef21ac2d8b18add447474dcd41c7041`.

These are noiseless sampler buckets computed offline. They demonstrate a candidate plaintext classifier; network timing still requires an empirical error-rate measurement.
