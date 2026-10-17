# AGENTS.md — EdrEval-Sample-Factory（Harness）

> 从 `EdrEvalAgent` 剥离的 **Harness** 控制面：终端（主机侧）样本生成与功能真值验证。目标：少犯本项目特有的错。

## 1. 项目事实

- **产品名：Harness** = 设计书中的 **流水线 A**。职责是终端样本生成（插件成形、组合生产、实验室功能真值），不是在线战役。
- **不做**：在线 dispatch、Sliver 战役剧场、自研植入体。
- **产物边界**：本仓只持控制面；插件源码/二进制/catalog 在 `EdrEval-Sample-Factory-Repository`。
- **权威设计**：`docs/superpowers/specs/2026-08-27-sample-factory-pipeline-design.md`；PH 行听 `docs/coverage/procedure-host-ttp-coverage-matrix.md`。
- **`PH` = Procedure / Host**：主机侧可复现步骤行 ID（`ph_id` / `PH-*`）。不是 Phishing、不是 Playbook、不是 ATT&CK T 编号。权威矩阵：`docs/coverage/procedure-host-ttp-coverage-matrix.md`。
- **勿混淆**：项目名 **Harness** ≠ 组件 **Plugin Harness**（VMware 单插件验证执行器）。

## 2. 硬边界

1. 密钥不进 Markdown / 日志；只用 `secret://`、`lab-secret://`。
2. 载荷二进制不入库。
3. 不虚构 ATT&CK / 检测可见性 / PH 行（未建行不得发明 `PH-*`）。
4. Harness LLM 不得获得在线 dispatch 权。

## 3. 验证

```bash
python -m unittest discover -s tests -p "test_sample_factory*.py"
python -m unittest discover -s tests -p "test_factory_*.py"
python -m unittest tests.test_plugin_harness_oracles -v
```

## 4. Do Not

- 不把「文档没写」补成「看起来写了」。
- 不未经确认 push 远端或改分支保护。
- 不提交 `secrets.env`、VM 证书、载荷二进制。
