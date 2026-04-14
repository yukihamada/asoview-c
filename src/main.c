#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mongoose.h"
#include "db.h"
#include "seed.h"
#include "handlers.h"
#include "admin.h"
#include "rate_limit.h"

static void event_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;
    sqlite3 *db = (sqlite3 *)c->fn_data;

    char uri[256] = {0};
    snprintf(uri, sizeof(uri), "%.*s", (int)hm->uri.len, hm->uri.buf);

    /* IP ベースレート制限 */
    char client_ip[48] = {0};
    mg_snprintf(client_ip, sizeof(client_ip), "%M", mg_print_ip, &c->rem);
    int is_auth_ep = (strncmp(hm->uri.buf, "/api/v1/auth", 12) == 0 ||
                      strncmp(hm->uri.buf, "/api/v1/users", 13) == 0);
    if (rate_check(client_ip, is_auth_ep)) {
        mg_http_reply(c, 429, "Content-Type: application/json\r\n",
                      "{\"error\":\"リクエスト数が多すぎます。しばらく経ってから再試行してください\"}");
        return;
    }

    long id = 0;
    char booking_id[64] = {0};

#define IS_GET    (mg_strcmp(hm->method, mg_str("GET"))    == 0)
#define IS_POST   (mg_strcmp(hm->method, mg_str("POST"))   == 0)
#define IS_PATCH  (mg_strcmp(hm->method, mg_str("PATCH"))  == 0)
#define IS_DELETE (mg_strcmp(hm->method, mg_str("DELETE")) == 0)
#define IS_PUT    (mg_strcmp(hm->method, mg_str("PUT"))    == 0)

    /* ── Public endpoints ─────────────────────────────────────── */
    if (strcmp(uri, "/api/v1/health") == 0) {
        if (IS_GET) handle_health(c, hm, db);

    } else if (strcmp(uri, "/api/v1/areas") == 0) {
        if (IS_GET) handle_list_areas(c, hm, db);

    } else if (strcmp(uri, "/api/v1/categories") == 0) {
        if (IS_GET) handle_list_categories(c, hm, db);

    } else if (strcmp(uri, "/api/v1/venues") == 0) {
        if (IS_GET) handle_list_venues(c, hm, db);

    } else if (sscanf(uri, "/api/v1/venues/%ld/plans", &id) == 1
               && strstr(uri, "/plans") != NULL) {
        if (IS_GET) handle_list_venue_plans(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/venues/%ld", &id) == 1
               && strstr(uri, "/plans") == NULL) {
        if (IS_GET) handle_get_venue(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/plans/%ld/schedules", &id) == 1
               && strstr(uri, "/schedules") != NULL) {
        if (IS_GET) handle_list_schedules(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/plans/%ld/reviews", &id) == 1
               && strstr(uri, "/reviews") != NULL) {
        if (IS_GET) handle_list_plan_reviews(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/plans") == 0) {
        if (IS_GET) handle_list_plans(c, hm, db);

    } else if (sscanf(uri, "/api/v1/plans/%ld", &id) == 1
               && strstr(uri, "/schedules") == NULL
               && strstr(uri, "/reviews") == NULL) {
        if (IS_GET) handle_get_plan(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/users") == 0) {
        if (IS_POST) handle_create_user(c, hm, db);

    } else if (sscanf(uri, "/api/v1/users/%ld/bookings", &id) == 1
               && strstr(uri, "/bookings") != NULL) {
        if (IS_GET) handle_list_user_bookings(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/users/%ld/bookmarks", &id) == 1
               && strstr(uri, "/bookmarks") != NULL) {
        if (IS_GET) handle_list_user_bookmarks(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/users/%ld", &id) == 1
               && strstr(uri, "/bookings") == NULL
               && strstr(uri, "/bookmarks") == NULL) {
        if (IS_GET)   handle_get_user(c, hm, db, id);
        else if (IS_PATCH) handle_update_user(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/auth/login") == 0) {
        if (IS_POST) handle_login(c, hm, db);

    } else if (strcmp(uri, "/api/v1/bookings") == 0) {
        if (IS_POST) handle_create_booking(c, hm, db);

    } else if (sscanf(uri, "/api/v1/bookings/%36[^/]", booking_id) == 1) {
        /* check suffix after the UUID to distinguish /:id vs /:id/cancel */
        size_t pfx = strlen("/api/v1/bookings/") + strlen(booking_id);
        if (strcmp(uri + pfx, "/cancel") == 0) {
            if (IS_PATCH) handle_cancel_booking(c, hm, db, booking_id);
        } else if (uri[pfx] == '\0') {
            if (IS_GET) handle_get_booking(c, hm, db, booking_id);
        } else {
            mg_http_reply(c, 404, "Content-Type: application/json\r\n", "{\"error\":\"not found\"}");
        }

    } else if (strcmp(uri, "/api/v1/reviews") == 0) {
        if (IS_POST) handle_create_review(c, hm, db);

    } else if (strcmp(uri, "/api/v1/search") == 0) {
        if (IS_GET) handle_search(c, hm, db);

    } else if (strcmp(uri, "/api/v1/webhooks/stripe") == 0) {
        if (IS_POST) handle_stripe_webhook(c, hm, db);

    } else if (strcmp(uri, "/api/v1/bookmarks") == 0) {
        if (IS_POST) handle_create_bookmark(c, hm, db);

    } else if (sscanf(uri, "/api/v1/bookmarks/%ld", &id) == 1) {
        if (IS_DELETE) handle_delete_bookmark(c, hm, db, id);

    /* Admin endpoints: /api/v1/admin/ ──────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/venues") == 0) {
        if (IS_POST) handle_admin_create_venue(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/venues/%ld", &id) == 1) {
        if (IS_PATCH)  handle_admin_update_venue(c, hm, db, id);
        else if (IS_DELETE) handle_admin_delete_venue(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/admin/plans") == 0) {
        if (IS_POST) handle_admin_create_plan(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/plans/%ld/schedules", &id) == 1
               && strstr(uri, "/schedules") != NULL) {
        if (IS_POST) handle_admin_create_schedule(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/plans/%ld/prices", &id) == 1
               && strstr(uri, "/prices") != NULL) {
        if (IS_PUT) handle_admin_set_prices(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/plans/%ld", &id) == 1
               && strstr(uri, "/schedules") == NULL
               && strstr(uri, "/prices") == NULL) {
        if (IS_PATCH)  handle_admin_update_plan(c, hm, db, id);
        else if (IS_DELETE) handle_admin_delete_plan(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/schedules/%ld", &id) == 1) {
        if (IS_DELETE) handle_admin_delete_schedule(c, hm, db, id);

    } else {
        mg_http_reply(c, 404, "Content-Type: application/json\r\n",
                      "{\"error\":\"not found\"}");
    }
#undef IS_GET
#undef IS_POST
#undef IS_PATCH
#undef IS_DELETE
#undef IS_PUT
}

int main(int argc, char *argv[]) {
    const char *db_path = getenv("DATABASE_URL");
    if (!db_path) db_path = "asoview.db";
    const char *port = getenv("PORT");
    if (!port) port = "3001";
    if (argc >= 2) db_path = argv[1];
    if (argc >= 3) port = argv[2];

    /* ── セキュリティ起動チェック ──────────────────────────────────── */
    const char *jwt_secret   = getenv("JWT_SECRET");
    const char *admin_key    = getenv("ADMIN_KEY");
    const char *stripe_sk    = getenv("STRIPE_SECRET_KEY");
    const char *stripe_whsec = getenv("STRIPE_WEBHOOK_SECRET");

    if (!jwt_secret || !*jwt_secret) {
        fprintf(stderr,
            "[WARN] JWT_SECRET is not set — using insecure default. "
            "Set JWT_SECRET in production!\n");
    } else if (strlen(jwt_secret) < 32) {
        fprintf(stderr,
            "[WARN] JWT_SECRET is too short (%zu chars). "
            "Use at least 32 random characters.\n", strlen(jwt_secret));
    }
    if (!admin_key || !*admin_key) {
        fprintf(stderr,
            "[WARN] ADMIN_KEY is not set — using insecure default. "
            "Set ADMIN_KEY in production!\n");
    }
    if (stripe_sk && *stripe_sk && (!stripe_whsec || !*stripe_whsec)) {
        fprintf(stderr,
            "[WARN] STRIPE_SECRET_KEY is set but STRIPE_WEBHOOK_SECRET is missing. "
            "Webhooks will be rejected.\n");
    }

    sqlite3 *db = db_open(db_path);
    if (!db) return 1;
    seed_if_empty(db);

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);

    char listen_addr[64];
    snprintf(listen_addr, sizeof(listen_addr), "0.0.0.0:%s", port);
    if (!mg_http_listen(&mgr, listen_addr, event_handler, db)) {
        fprintf(stderr, "Failed to listen on %s\n", listen_addr);
        return 1;
    }
    printf("[asoview-c] Listening on http://%s\n", listen_addr);

    for (;;) mg_mgr_poll(&mgr, 100);

    mg_mgr_free(&mgr);
    db_close(db);
    return 0;
}
