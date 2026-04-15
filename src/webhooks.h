#pragma once
#include "db.h"

/* パートナー向け Webhook 配信
 *
 * イベント名:
 *   "booking.created"   — 予約確定時
 *   "booking.cancelled" — 予約キャンセル時
 *   "booking.refunded"  — 返金処理時
 *
 * 各エンドポイントの events JSON 配列にマッチする場合のみ配信。
 * X-Asoview-Event: <event> ヘッダーと
 * X-Asoview-Signature: sha256=<hmac-hex> ヘッダーを付与して POST する。
 */

void webhooks_fire(DbConn *db, const char *event, const char *payload_json);
