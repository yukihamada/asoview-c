#pragma once
#include "db_driver.h"

/* 管理者操作の監査ログを audit_logs テーブルに記録する */
void audit_log(DbConn *db, const char *actor, const char *action,
               const char *target_type, const char *target_id,
               const char *detail, const char *ip);
