# Per-index first-row probes

For each target index `i`, set `C1[0,0]=a`, all other C1 entries to zero, and use the listed C2 first row. The ten non-target secret coefficients were exhaustively varied over `{-1,0,+1}` (`59049` cases per target value). `mismatch=0` means the decoded message was invariant across those cases.

The second probe is made by changing only `C2[0,i]` by the listed signed step. The two bucket outputs then form a unique code for `s_i=-1,0,+1`.

The table below uses one deterministic level-256 SHAKE public key and the same key for both probes. Bucket labels therefore agree within the table; they are not universal labels for another public key.

| i | a | C2 first row | first buckets (-1,0,+1) | second C2 change | second buckets |
|---:|---:|---|---|---:|---|
| 0 | 1 | `256,0,576,512,256,128,192,512,384,896,576` | `53,53,54` | `C2[0,0] -= 1` | `53,54,54` |
| 1 | 8 | `768,512,768,320,256,960,448,0,896,0,576` | `54,53,53` | `C2[0,1] += 8` | `54,54,53` |
| 2 | 1 | `256,256,512,128,960,0,768,640,512,960,384` | `54,54,53` | `C2[0,2] -= 1` | `54,53,53` |
| 3 | 4 | `64,64,448,256,576,64,832,256,576,640,704` | `54,53,53` | `C2[0,3] += 4` | `54,54,53` |
| 4 | 2 | `704,512,384,512,512,64,256,576,768,384,320` | `53,53,54` | `C2[0,4] -= 2` | `53,54,54` |
| 5 | 1 | `448,768,384,640,960,256,0,576,576,960,640` | `54,53,53` | `C2[0,5] += 1` | `54,54,53` |
| 6 | 16 | `128,768,768,0,192,64,768,768,64,768,256` | `54,54,53` | `C2[0,6] -= 16` | `54,53,53` |
| 7 | 4 | `0,640,640,832,704,320,704,0,512,448,960` | `54,53,53` | `C2[0,7] += 4` | `54,54,53` |
| 8 | 1 | `320,256,128,128,128,0,960,512,512,256,128` | `53,54,54` | `C2[0,8] += 1` | `53,53,54` |
| 9 | 2 | `896,256,512,768,256,448,320,768,0,768,384` | `53,54,54` | `C2[0,9] += 2` | `53,53,54` |
| 10 | 4 | `512,128,256,640,640,448,832,704,512,640,768` | `53,53,54` | `C2[0,10] -= 4` | `53,54,54` |

For every listed probe and shifted probe, all three `mismatch` counts were zero. The opposite-sign shifts were also checked as controls; they do not give a three-way partition for indices 1, 8, or 9. Indices 5 and 7 now have candidates after the additional exhaustive search; the earlier failed random search was not an impossibility result.

The complete-KEM check is in `recover_all_indices.c`. It generates one real key, moves the nonzero coefficient through every `C1[0,k]` position (`k=0..1183`), sends both probes for each position through `scloud_kemdecaps`, records the instrumented sampler bucket, and compares it with all three offline predictions for the 11 output coordinates. The run `recover-all-indices.csv` ended with `full KEM two-probe matrix recovery: PASS (13024/13024 entries)`, with zero bucket mismatches. This covers the complete `11 x 1184` secret matrix for that key and probe set; it is not a claim that timing noise or a remote oracle has been measured.
