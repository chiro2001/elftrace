#!/usr/bin/env python3
"""预创建线程池的 HTTP 文件服务 (http_pool)。

与 ThreadingHTTPServer (每请求 clone 线程) 不同: 启动时创建固定数量
worker, 请求通过 ThreadPoolExecutor 提交, 窗口内不再有 clone3。
用于验证"线程已稳定"窗口是多线程 HTTP 的支持层负载。

用法: http_pool_server.py <port> <directory> [workers]
"""
import concurrent.futures
import functools
import http.server
import os
import sys


class PoolHTTPServer(http.server.HTTPServer):
    def __init__(self, addr, handler, workers=4):
        super().__init__(addr, handler)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request,
                         client_address)

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        finally:
            self.shutdown_request(request)

    def server_close(self):
        self.pool.shutdown(wait=False)
        super().server_close()


def main():
    port = int(sys.argv[1])
    directory = sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=directory)
    with PoolHTTPServer(("127.0.0.1", port), handler, workers=workers) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
