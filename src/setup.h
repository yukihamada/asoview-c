/*
 * setup.h — セットアップウィザード（初期キー設定画面）
 *
 * GET  /setup           → キー入力フォームを返す
 * POST /api/v1/setup    → .env ファイルへ書き込み（デフォルトキー時のみ許可）
 */
#pragma once
#include "mongoose.h"
#include "db_driver.h"

void handle_setup_page(struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_setup_save(struct mg_connection *c, struct mg_http_message *hm, DbConn *db);

/* デフォルトキーで動作中か判定（admin dashboard の警告バナー表示に使用） */
int setup_is_unconfigured(void);
