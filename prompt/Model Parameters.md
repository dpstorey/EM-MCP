These are the model parameters used in the development and testing of this MCP:
* GPUs: 2x Nvidia A6000 (Ampere) with NVLINK (VRAM 48G+48G)
* CPU: AMD Epyc 1702
* RAM: 256G
* OS: Ubuntu 26.04
* LLama.cpp version: 0.3.0-dev (build 10711, commit 9723942ad), built with GNU 15.2.0 for Linux x86_64

Both models will fit on 1 GPU
## HCompany Holo-3.1-35B-A3B, (Qwen 3.1-35B-A3B)

| Parameter          | Value                        |
| ------------------ | ---------------------------- |
| Model              | Holo-3.1-35B-A3B-Q6_K.gguf   |
| VRAM				 | 28.5 GB					    |
| cache-type-{k/v}   | 8                            |
| Max Context Tokens | 262144                       |
| Max Output Tokens  | 16384                        |
| Temperature        | 0.2                          |
| Top P              | 0.95                         |
| Frequency          | 0.0                          |
| Prescence Penalty  | 0.0                          |
| Reasoning:         | Medium                       |
| Split              | layer                        |

## Qwen 3.8-27B
| Parameter          | Value                       |
| ------------------ | --------------------------- |
| Model              | Qwen3.8-27B-UD-Q6_K_XL.gguf |
| VRAM				 | 25.3 GB					   |
| cache-type-{k/v}   | 8                           |
| Max Context Tokens | 262144                      |
| Max Output Tokens  | 16384                       |
| Temperature        | 0.2                         |
| Top P              | 0.95                        |
| Frequency          | 0.0                         |
| Prescence Penalty  | 0.0                         |
| Repeat Penalty     | 1.0                         |
| Reasoning:         | None                        |
| Tensor split       | 1:1                         |
| Split mode         | tensor                      |
| Spec type          | draft-mtp                   |
| depc-draft-n-max   | 3                           |