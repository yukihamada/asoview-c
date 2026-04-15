#include "audit.h"
#include <stdio.h>

void audit_log(DbConn *db, const char *actor, const char *action,
               const char *target_type, const char *target_id,
               const char *detail, const char *ip) {
    DbStmt *st = db_prepare(db,
        "INSERT INTO audit_logs(actor,action,target_type,target_id,detail,ip)"
        " VALUES(?,?,?,?,?,?)");
    if (!st) return;
    db_bind_text(st, 1, actor       ? actor       : "admin");
    db_bind_text(st, 2, action);
    db_bind_text(st, 3, target_type ? target_type : "");
    db_bind_text(st, 4, target_id   ? target_id   : "");
    db_bind_text(st, 5, detail      ? detail      : "");
    db_bind_text(st, 6, ip          ? ip          : "");
    db_step(st);
    db_finalize(st);
}
