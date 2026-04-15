#pragma once
#include <stddef.h>

/* UUID v4 (RFC 4122) — buf must be at least 37 bytes */
void generate_uuid(char *buf);

/* PBKDF2-SHA256 パスワードハッシュ / 検証
   hash_out に "pbkdf2$<hex-salt>$<hex-dk>" を書き込む (out_len >= 100) */
int  hash_password(const char *password, char *hash_out, size_t out_len);
int  verify_password(const char *password, const char *stored_hash);

/* 文字列ユーティリティ */
char *str_lower(char *s);               /* in-place lowercase */
int   str_starts_with(const char *s, const char *prefix);

/* JWT (HS256) ― platform.h 経由で HMAC-SHA256 を使用
   jwt_create: malloc で確保したトークン文字列を返す。呼び出し元が free() すること。
   jwt_verify: user_id を返す。無効/期限切れなら -1 */
char *jwt_create(long user_id, const char *secret);
long  jwt_verify(const char *token, const char *secret);

/* LIKE パターンの % _ ! をエスケープ（'!' エスケープ文字方式、全バックエンド共通）
   LIKE ... ESCAPE '!' と組み合わせて使う */
void escape_like(const char *src, char *dst, size_t dst_len);

/* メールアドレスの簡易バリデーション */
int is_valid_email(const char *email);

/* SHA-256 ハッシュを 64 文字 hex 文字列に変換（out は 65 バイト以上必須） */
void sha256_hex(const char *input, size_t input_len, char out[65]);
