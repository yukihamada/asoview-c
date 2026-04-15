#pragma once
#include "mongoose.h"
#include "db_driver.h"

/* 管理者API — X-Admin-Key ヘッダで認証 */
/* Venues */
void handle_admin_list_venues    (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_create_venue   (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_update_venue   (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
void handle_admin_delete_venue   (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
/* Plans */
void handle_admin_list_plans     (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_create_plan    (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_update_plan    (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
void handle_admin_delete_plan    (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
/* Schedules */
void handle_admin_create_schedule(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long plan_id);
void handle_admin_update_schedule(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
void handle_admin_delete_schedule(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
/* Prices */
void handle_admin_set_prices     (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long plan_id);
/* Bookings */
void handle_admin_list_bookings  (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
/* Reviews */
void handle_admin_list_reviews   (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_delete_review  (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
/* Users */
void handle_admin_list_users     (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
/* Bulk schedule generation */
void handle_admin_bulk_create_schedules(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long plan_id);
/* Refund */
void handle_admin_refund_booking (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, const char *id);
/* DB Backup */
void handle_admin_backup_db      (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
/* Admin WebUI */
void handle_admin_ui             (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
/* Audit Logs */
void handle_admin_audit_logs     (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
/* Sales Report CSV */
void handle_admin_sales_report   (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
/* Webhooks */
void handle_admin_list_webhooks  (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_create_webhook (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_delete_webhook (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
/* Coupons */
void handle_admin_list_coupons   (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_create_coupon  (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_delete_coupon  (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
/* Plan Images */
void handle_admin_list_plan_images  (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long plan_id);
void handle_admin_create_plan_image (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long plan_id);
void handle_admin_delete_plan_image (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long img_id);
/* Admin 2FA */
void handle_admin_2fa_setup         (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
/* Tenants */
void handle_admin_list_tenants      (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_create_tenant     (struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_admin_get_tenant        (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
void handle_admin_update_tenant     (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
void handle_admin_delete_tenant     (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
