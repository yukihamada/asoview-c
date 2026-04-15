#pragma once
#include <stddef.h>

void metrics_init(void);
void metrics_incr_req(void);
void metrics_incr_4xx(void);
void metrics_incr_5xx(void);
void metrics_render(char *buf, size_t size);
