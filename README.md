# ZTrust

轻量化零信任访问代理与审计网关第一阶段原型。

当前代码提供一个可启动的 Go 控制面，覆盖：

- 本地账号登录、退出和 Cookie 登录态
- 网关侧 `GET /auth/check` 鉴权接口
- 用户、用户组、应用、授权策略的最小管理 API
- 访问日志、登录日志、管理操作日志
- OpenResty / Nginx 七层反向代理配置样例
- MySQL 第一版表结构

## 快速启动

```sh
cp configs/env.example .env
export ZTRUST_ADMIN_PASSWORD='change-me'
export ZTRUST_SEED_APP_DOMAIN='www.e-cology.com.cn'
export ZTRUST_SEED_APP_BACKEND='http://10.0.0.10'
go run ./cmd/ztrustd
```

默认监听 `:8080`。如果未设置环境变量，会创建 `admin / admin123456` 管理员，仅适合本地验证。

启动后访问 `http://127.0.0.1:8080/` 可进入轻量管理后台。后台支持应用、用户、用户组、授权策略维护，以及访问日志、登录日志、管理操作日志查询。

## 后端接口

管理后台使用同一个 Go 服务提供接口：

- `POST /auth/login`、`POST /auth/logout`：登录与退出
- `GET /auth/check`：OpenResty 网关鉴权
- `GET /admin/me`：当前管理员信息
- `GET /admin/apps`、`POST /admin/apps`、`PUT /admin/apps/{id}`、`DELETE /admin/apps/{id}`：应用管理
- `GET /admin/users`、`POST /admin/users`、`PUT /admin/users/{id}`、`DELETE /admin/users/{id}`：用户管理
- `GET /admin/groups`、`POST /admin/groups`、`PUT /admin/groups/{id}`、`DELETE /admin/groups/{id}`：用户组管理
- `GET /admin/policies`、`POST /admin/policies`、`DELETE /admin/policies/{id}`：授权策略
- `POST /audit/access`、`POST /audit/admin`：网关访问审计与管理操作审计写入
- `GET /admin/audit/access`、`GET /admin/audit/login`、`GET /admin/audit/admin`：审计查询

## 基础调用

登录：

```sh
curl -i -X POST http://127.0.0.1:8080/auth/login \
  -H 'Content-Type: application/json' \
  -c cookie.txt \
  -d '{"username":"admin","password":"change-me"}'
```

创建 OA 应用：

```sh
curl -b cookie.txt -X POST http://127.0.0.1:8080/admin/apps \
  -H 'Content-Type: application/json' \
  -d '{"name":"e-cology OA","domain":"www.e-cology.com.cn","backend_url":"http://10.0.0.10","enabled":true}'
```

创建用户授权策略：

```sh
curl -b cookie.txt -X POST http://127.0.0.1:8080/admin/policies \
  -H 'Content-Type: application/json' \
  -d '{"app_id":2,"subject":"user","subject_id":3,"effect":"allow"}'
```

查询访问日志：

```sh
curl -b cookie.txt 'http://127.0.0.1:8080/admin/audit/access?username=zhangsan&ip=192.0.2.10&path=/workflow&status_code=200&limit=50'
```

## OpenResty 接入

参考 [deployments/openresty/ztrust_oa.conf](/Users/a12345/AI/ZTrust/deployments/openresty/ztrust_oa.conf)，需要安装 `lua-resty-http` 和 `lua-cjson`。第一阶段建议先接 OA 测试环境，完成页面、登录、跳转、Cookie、附件上传下载、移动端访问验证后再灰度。

## 数据库

表结构在 [db/schema.sql](/Users/a12345/AI/ZTrust/db/schema.sql)。当前 Go 原型使用内存存储，便于快速跑通链路；下一步可将 `internal/store` 替换为 MySQL 与 Redis 实现。
