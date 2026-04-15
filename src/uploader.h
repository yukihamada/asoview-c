#pragma once
#include "mongoose.h"
#include <sqlite3.h>

/* 管理者向け S3 presigned PUT URL 発行
   環境変数: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET, AWS_S3_REGION
   リクエスト: POST {"filename":"plan.jpg","content_type":"image/jpeg"}
   レスポンス: {"url":"https://...","key":"uploads/uuid.jpg"} */
void handle_admin_get_upload_url(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
