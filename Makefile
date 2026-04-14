CC      = cc
STD     = -std=c11
WARN    = -Wall -Wextra -Wno-unused-parameter
INC     = -Ideps -Isrc
DEFS    = -DMG_ENABLE_LOG=0

LDFLAGS = -lsqlite3 -lcurl -framework Security -framework CoreFoundation

SRCS    = deps/mongoose.c deps/cJSON.c \
          src/utils.c src/db.c src/seed.c src/handlers.c src/admin.c src/stripe.c src/rate_limit.c

BIN     = asoview-c
TEST    = tests/run_tests

.PHONY: all test clean schema

all: $(BIN)

$(BIN): $(SRCS) src/main.c src/schema_embed.h
	$(CC) $(STD) $(WARN) $(INC) $(DEFS) -O2 \
	    $(SRCS) src/main.c $(LDFLAGS) -o $@

$(TEST): $(SRCS) tests/test_api.c src/schema_embed.h
	$(CC) $(STD) $(WARN) $(INC) $(DEFS) -O0 -g \
	    $(SRCS) tests/test_api.c $(LDFLAGS) -lcurl -o $@

test: $(BIN) $(TEST)
	./$(TEST)

schema:
	python3 scripts/gen_schema_embed.py

clean:
	rm -f $(BIN) $(TEST) *.db tests/*.db
