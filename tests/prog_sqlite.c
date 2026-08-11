/* 真实场景负载: sqlite3 文件库事务负载 (INSERT 批 + COUNT/SUM 查询)。
 * 每轮一个事务 200 行 + 聚合查询, 触发 B-tree 页缓存/alloc/文件
 * syscall (open/write/fsync/close); 供 strict baremetal 切片验证
 * syscall 回放 + alloc replay + 零中间 syscall。 */
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 300;
    const char *path = argc > 2 ? argv[2] : "/tmp/elftrace_sqlite.db";
    remove(path);

    sqlite3 *db = NULL;
    char *err = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK)
        return 2;
    if (sqlite3_exec(db,
                     "PRAGMA synchronous=OFF;"
                     "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT, c REAL);",
                     NULL, NULL, &err) != SQLITE_OK)
        return 3;

    sqlite3_stmt *ins = NULL, *q = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO t(a,b,c) VALUES(?1,?2,?3)",
                           -1, &ins, NULL) != SQLITE_OK)
        return 4;

    printf("READY\n");
    fflush(stdout);
    usleep(300000);

    uint64_t sum = 0;
    char buf[64];
    int key = 0;
    for (int r = 0; r < rounds; r++) {
        if (sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK)
            return 5;
        for (int i = 0; i < 200; i++) {
            key++;
            sqlite3_bind_int(ins, 1, key);
            snprintf(buf, sizeof(buf), "row-%d-%d", r, i);
            sqlite3_bind_text(ins, 2, buf, -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(ins, 3, (double)(r * 1000 + i) / 7.0);
            if (sqlite3_step(ins) != SQLITE_DONE)
                return 6;
            sqlite3_reset(ins);
            sqlite3_clear_bindings(ins);
        }
        if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK)
            return 7;
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*), SUM(a) FROM t;",
                               -1, &q, NULL) != SQLITE_OK)
            return 8;
        if (sqlite3_step(q) == SQLITE_ROW)
            sum += (uint64_t)sqlite3_column_int64(q, 1);
        sqlite3_finalize(q);
        q = NULL;
    }

    sqlite3_finalize(ins);
    sqlite3_close(db);
    remove(path);
    printf("SQLITE sum=%llu\n", (unsigned long long)sum);
    return (int)(sum % 255);
}
