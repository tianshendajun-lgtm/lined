#pragma once
#include <stdint.h>
#include <stdbool.h>

/*
 * 方案 B：Swift 钩子回调到 C 的接口（都在 Tweak.m 里实现，非 static 导出）。
 * Swift 侧通过 -import-objc-header 这个头文件调用。
 */

// 该 host 是否要走本地中继（legy / uts-front）
bool la_host_should_relay_c(const char *host);

// 把真实目标登记到中继待处理队列（供 relay 建 CONNECT 用）
bool la_pending_push_c(const char *host, uint16_t port, int32_t slot);

// 当前账号槽（选中优先，否则 activeSlot）
int32_t la_current_slot_c(void);

// 本地中继监听端口（0 = 未就绪）
uint16_t la_relay_port_c(void);

// 是否强制关闭代理（.proxy_off 存在）
bool la_proxy_off_c(void);
