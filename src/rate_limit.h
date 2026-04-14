#pragma once

/*
 * シンプルな IP ベースレート制限（in-memory, スレッドセーフ不要: mongoose 単一スレッド）
 *
 * rate_check(ip, is_auth)
 *   返り値: 0 = OK, 1 = レート超過
 *
 * 制限:
 *   一般エンドポイント: 120 req/min per IP
 *   認証エンドポイント: 10 req/min per IP（ブルートフォース防止）
 */
int rate_check(const char *ip, int is_auth);
