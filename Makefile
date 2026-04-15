CC      = cc
STD     = -std=c11
WARN    = -Wall -Wextra -Wno-unused-parameter
INC     = -Ideps -Isrc
DEFS    = -DMG_ENABLE_LOG=0

# データベースバックエンド選択: sqlite (デフォルト) / postgres / mysql
DB ?= sqlite

# プラットフォーム別リンクフラグ
UNAME := $(shell uname)

# Linux (glibc) では POSIX + BSD 拡張を有効化 (strncasecmp, CLOCK_REALTIME 等)
ifneq ($(UNAME), Darwin)
    DEFS += -D_DEFAULT_SOURCE
endif

ifeq ($(DB), postgres)
    DEFS    += -DUSE_POSTGRES
    DB_SRCS  = src/db_postgres.c
    ifeq ($(UNAME), Darwin)
        PG_INC   := $(shell pg_config --includedir 2>/dev/null)
        ifeq ($(PG_INC),)
            $(error PostgreSQL headers not found. Run: brew install libpq && brew link libpq --force)
        endif
        INC     += -I$(PG_INC)
        LDFLAGS += -lpq
    else
        ifeq ($(wildcard /usr/include/postgresql/libpq-fe.h),)
            $(error PostgreSQL headers not found. Run: sudo apt-get install libpq-dev)
        endif
        INC     += -I/usr/include/postgresql
        LDFLAGS += -lpq
    endif
    DB_LABEL = PostgreSQL
else ifeq ($(DB), mysql)
    DEFS    += -DUSE_MYSQL
    DB_SRCS  = src/db_mysql.c
    ifeq ($(UNAME), Darwin)
        MYSQL_INC := $(shell mysql_config --include 2>/dev/null)
        ifeq ($(MYSQL_INC),)
            $(error MySQL headers not found. Run: brew install mysql-client && export PATH="$$(brew --prefix mysql-client)/bin:$$PATH")
        endif
        MYSQL_LIB := $(shell mysql_config --libs 2>/dev/null)
        INC     += $(MYSQL_INC)
        LDFLAGS += $(MYSQL_LIB)
    else
        ifeq ($(shell which mysql_config 2>/dev/null),)
            $(error mysql_config not found. Run: sudo apt-get install default-libmysqlclient-dev)
        endif
        INC     += $(shell mysql_config --include)
        LDFLAGS += $(shell mysql_config --libs)
    endif
    DB_LABEL = MySQL
else
    # SQLite (default)
    DB_SRCS  =
    DB_LABEL = SQLite
endif

# 共通リンクフラグ（プラットフォーム別）
ifeq ($(UNAME), Darwin)
    LDFLAGS += -lsqlite3 -lcurl -lpthread -framework Security -framework CoreFoundation
else
    LDFLAGS += -lsqlite3 -lcurl -lpthread -lssl -lcrypto
endif

SRCS    = deps/mongoose.c deps/cJSON.c \
          src/utils.c src/db.c src/seed.c src/handlers.c src/admin.c \
          src/stripe.c src/mailer.c src/rate_limit.c src/platform.c src/uploader.c \
          src/metrics.c src/waitlist.c src/setup.c $(DB_SRCS)

BIN     = asoview-c
TEST    = tests/run_tests

ASAN_TEST = tests/run_tests_asan

.PHONY: all test test-asan clean schema info

all: $(BIN)

info:
	@echo "DB backend: $(DB_LABEL) (DB=$(DB))"

$(BIN): $(SRCS) src/main.c src/schema_embed.h
	$(CC) $(STD) $(WARN) $(INC) $(DEFS) -O2 \
	    $(SRCS) src/main.c $(LDFLAGS) -o $@
	@echo "Built $(BIN) [$(DB_LABEL)]"

$(TEST): $(SRCS) tests/test_api.c src/schema_embed.h
	$(CC) $(STD) $(WARN) $(INC) $(DEFS) -O0 -g \
	    $(SRCS) tests/test_api.c $(LDFLAGS) -o $@

test: $(BIN) $(TEST)
	./$(TEST)

# ASAN / UBSAN ビルド＆テスト（メモリ安全性チェック）
# $(BIN) を先にビルド: テストランナーがサーバーバイナリ ./asoview-c を起動するため
$(ASAN_TEST): $(BIN) $(SRCS) tests/test_api.c src/schema_embed.h
	$(CC) $(STD) $(WARN) $(INC) $(DEFS) -O0 -g \
	    -fsanitize=address,undefined -fno-omit-frame-pointer \
	    $(SRCS) tests/test_api.c $(LDFLAGS) -o $@

test-asan: $(ASAN_TEST)
	ASAN_OPTIONS=detect_leaks=0 ./$(ASAN_TEST)

schema:
	python3 scripts/gen_schema_embed.py

clean:
	rm -f $(BIN) $(TEST) $(ASAN_TEST) *.db tests/*.db
