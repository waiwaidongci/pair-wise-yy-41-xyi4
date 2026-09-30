# 桥梁结构监测与限行决策

融合传感、巡检、交通荷载和天气数据，生成限载限行或恢复建议。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8318
```

默认端口为`8318`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `POST /api/offline-batch`：离线批次补传，使用`batch_id`幂等重放
- `GET /api/audit?verify=1` 或 `GET /api/audit/verify`：校验审计链并返回出错事件编号
- `GET /api/audit`

允许角色：sensor_operator, bridge_engineer, traffic_authority, viewer。监测偏差与预警阈值之比和多条异常记录决定告警等级；限行与封闭决策必须绑定交通通告记录。

## 离线补传

`POST /api/offline-batch`按`batch_id`整批处理，批次内操作支持`偏差登记`、`异常事项`和`限行推进`（也兼容英文别名`deviation`、`issue`、`advance`）。每条操作可单独带`actor`和`role`；越权、跳级、引用缺失等不会改动已入库数据，而会进入响应中的`conflicts`清单。

补传的状态或记录变更与审计事件在同一事务提交。若服务端告警版本已经前进，`限行推进`忽略车辆端旧版本并按服务端当前状态和版本重新判定；`expected_version`会保留在审计详情中。同`batch_id`且同请求体重传时直接返回首次结果，不重复写业务数据或审计。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
