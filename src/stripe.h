#pragma once
#include <stddef.h>

/*
 * stripe_create_payment_intent
 *   amount_jpy    : 決済金額（円）
 *   booking_id    : 予約UUID（metadata に埋め込む）
 *   pi_id_out     : PaymentIntent ID を受け取るバッファ (pi_xxx...)
 *   pi_id_size    : バッファサイズ
 *   client_secret_out : client_secret を受け取るバッファ
 *   cs_size       : バッファサイズ
 * 返り値: 0=成功, -1=失敗
 */
int stripe_create_payment_intent(long amount_jpy,
                                 const char *booking_id,
                                 char *pi_id_out,        size_t pi_id_size,
                                 char *client_secret_out, size_t cs_size);

/*
 * stripe_verify_webhook
 *   sig_header     : Stripe-Signature ヘッダー値 (t=...,v1=...)
 *   payload        : リクエストボディ（生バイト）
 *   payload_len    : ボディ長
 *   webhook_secret : whsec_... 環境変数 STRIPE_WEBHOOK_SECRET
 * 返り値: 1=署名OK, 0=NG
 */
int stripe_verify_webhook(const char *sig_header,
                           const char *payload, size_t payload_len,
                           const char *webhook_secret);
