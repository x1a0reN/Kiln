# Kiln v0.1 计划（Unity IL2CPP 纵向闭环）
## 目标
- Windows-only
- stdio MCP（后续可扩展 streamable HTTP）
- Unity IL2CPP 纵向闭环可用
- 依赖 Il2CppDumper + IDA Pro 9.2（headless）+ Hex-Rays
- 输入游戏目录 -> 输出 MOD 包 + 安装说明 + 回滚脚本 + manifest

## 非目标
- UE 分支、Lua/Mono 注入暂不做
- 不做 GUI
- 不做 HTTP MCP

## 架构
```
Kiln/
  Kiln.Mcp/         # MCP stdio server（唯一对外入口）
  Kiln.Core/        # Workflow + Job + Artifact 管理
  Kiln.Plugins/
    Unity.Il2Cpp/   # Unity IL2CPP pipeline
    Ida.Pro/        # IDA 9.2 headless + export
    DotNetAnalysis/ # 程序集分析（后续扩展）
    Packaging/      # 打包、说明、回滚
```

## MCP 工具（对外）
### Workflow
- workflow.run(flow_name, params) -> job_id
- workflow.status(job_id) -> 进度 + 当前阶段
- workflow.logs(job_id) -> 日志尾
- workflow.cancel(job_id) -> 取消任务

### 基础步骤
- detect_engine(game_dir)
- unity_locate(game_dir)
- il2cpp_dump(game_dir, dumper_path, output_dir)
- ida_analyze(game_dir, ida_path, idb_dir)
- ida_export_symbols(job_id)
- ida_export_pseudocode(job_id)
- patch_codegen(requirements, analysis_artifacts)
- package_mod(output_dir)

## Unity IL2CPP 工作流
```
detect_engine
  -> unity_locate
  -> il2cpp_dump
  -> ida_analyze
  -> ida_export_symbols
  -> ida_export_pseudocode
  -> analysis_plan（AI 在外部生成；Kiln 负责产出上下文）
  -> patch_codegen
  -> package_mod
```

## 后台执行（长任务）
- ida_analyze 必须后台任务（返回 job_id）
- workflow.status/logs/cancel 对应状态查询、日志尾、取消

## 本地配置（不入库）
- `kiln.config.json`（本地配置，加入 .gitignore）
- `kiln.config.template.json`（模板，入库）
```json
{
  "idaPath": "D:\\\\Program Files\\\\IDA Professional 9.2\\\\idat64.exe",
  "il2cppDumperPath": "D:\\\\Tools\\\\Il2CppDumper",
  "workspaceRoot": "C:\\\\Kiln\\\\workspace"
}
```

## 风险与预案
- IDA 分析耗时：必须后台 Job + 允许取消
- Hex-Rays 许可：缺失则降级为符号/反汇编输出
- Il2CppDumper 兼容性：先做单版本，再扩展
