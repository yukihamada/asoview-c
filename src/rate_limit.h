#pragma once

/*
 * レート制限（in-memory, スレッドセーフ不要: mongoose 単一スレッド）
 *
 * rate_check(ip, is_auth)
 *   IP ベース。返り値: 0 = OK, 1 = レート超過
 *   制限:
 *     一般エンドポイント: 500 req/min per IP
 *     認証エンドポイント:  60 req/min per IP（ブルートフォース防止）
 *
 * rate_check_uid(uid)
 *   認証ユーザー単位の書き込み操作制限。返り値: 0 = OK, 1 = レート超過
 *   制限: 30 書き込み/min per user_id
 *   用途: 予約・レビュー・ブックマーク作成などの write 操作に適用
 */
int rate_check(const char *ip, int is_auth);
int rate_check_uid(long uid);
