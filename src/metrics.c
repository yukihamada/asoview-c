#include "metrics.h"
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

static _Atomic long g_req_total = 0;
static _Atomic long g_err_4xx   = 0;
static _Atomic long g_err_5xx   = 0;
static time_t g_start           = 0;

void metrics_init(void)     { g_start = time(NULL); }
void metrics_incr_req(void) { atomic_fetch_add(&g_req_total, 1); }
void metrics_incr_4xx(void) { atomic_fetch_add(&g_err_4xx, 1); }
void metrics_incr_5xx(void) { atomic_fetch_add(&g_err_5xx, 1); }

void metrics_render(char *buf, size_t size) {
    long uptime = (long)(time(NULL) - g_start);
    snprintf(buf, size,
        "# HELP asoview_requests_total Total HTTP requests processed\n"
        "# TYPE asoview_requests_total counter\n"
        "asoview_requests_total %ld\n"
        "# HELP asoview_errors_4xx_total Total 4xx client errors\n"
        "# TYPE asoview_errors_4xx_total counter\n"
        "asoview_errors_4xx_total %ld\n"
        "# HELP asoview_errors_5xx_total Total 5xx server errors\n"
        "# TYPE asoview_errors_5xx_total counter\n"
        "asoview_errors_5xx_total %ld\n"
        "# HELP asoview_uptime_seconds Server uptime in seconds\n"
        "# TYPE asoview_uptime_seconds gauge\n"
        "asoview_uptime_seconds %ld\n",
        atomic_load(&g_req_total),
        atomic_load(&g_err_4xx),
        atomic_load(&g_err_5xx),
        uptime);
}
