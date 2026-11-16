# Anchor gas, anvil-31337 (measured 2026-11-15T19:03:35Z)

40 mined `anchor()` transactions; contract `0x0c3f7d99302f3b669aa1fbfa70879b65363b4006`.

| metric | gas |
|---|---|
| deploy | 709850 |
| registerRecorder | 46294 |
| anchor, first for the recorder (cold `nextEpoch` slot) | 96171 |
| anchor, later (min / median / mean / max) | 81545 / 81569 / 81565.6 / 81569 |
| anchor, mean of all 40 | 81930.8 |

Cost per anchor from the MEASURED mean gas under STATED assumptions (ETH = $3,000; L2 execution gas only, L1 data fee excluded):

| L2 gas price | ETH / anchor | USD / anchor | USD / 100K anchors |
|---|---|---|---|
| 0.001 gwei | 8.193e-08 | $0.000246 | $24.58 |
| 0.01 gwei | 8.193e-07 | $0.002458 | $245.79 |
| 0.1 gwei | 8.193e-06 | $0.024579 | $2,457.92 |
| 1.0 gwei | 8.193e-05 | $0.245792 | $24,579.24 |

L1 data fee (OP Stack receipts): not present on this chain (Anvil): measure on Base Sepolia.
