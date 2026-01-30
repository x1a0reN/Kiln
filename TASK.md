# Kiln v0.1 任务清单（Unity IL2CPP 纵向闭环）
## Phase 0：工程重构
- [x] 项目更名为 Kiln
- [x] 移除 dnSpyEx 插件端相关代码
- [x] 只保留一个 console MCP server
- [x] 建立 Kiln.Core / Kiln.Mcp / Kiln.Plugins 目录结构

## Phase 1：Workflow + Job 管理
- [x] Job 状态机：Pending / Running / Completed / Failed / Canceled
- [x] Job 持久化：workspace/<job_id>/job.json
- [x] workflow.status / workflow.logs / workflow.cancel MCP 接口

## Phase 2：Unity 定位 + Il2CppDumper
- [ ] unity_locate：定位 GameAssembly.dll / global-metadata.dat
- [ ] il2cpp_dump：调用 Il2CppDumper（可配置）
- [ ] 输出 dump 目录 + 结构/映射文件

## Phase 3：IDA Headless 分析
- [ ] ida_analyze：idat64 -A -S 批处理分析
- [ ] 自动加载符号/类型信息
- [ ] 产出 .i64/.idb 与日志

## Phase 4：符号/伪代码导出
- [ ] ida_export_symbols：函数列表/签名导出
- [ ] ida_export_pseudocode：伪代码导出（Hex-Rays）
- [ ] 输出 JSON/文本作为分析上下文

## Phase 5：Patch & 打包
- [ ] patch_codegen：生成 patch / 插件骨架（模板）
- [ ] package_mod：产出 zip + install.md + rollback.ps1 + manifest.json
