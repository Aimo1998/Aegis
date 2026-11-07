//
//  AegisShim.h
//  Aegis
//
//  Swift 无法直接调用可变参数 syscall()，这里做一层 C 包装。
//

#ifndef AegisShim_h
#define AegisShim_h

#include <stdint.h>
#include <stdbool.h>

/// 直接走 SYS_lstat 原始系统调用（绕过 libc 层可能的 Hook）
int aegis_raw_lstat(const char *path, void *statBuf);

/// 直接走 SYS_stat
int aegis_raw_stat(const char *path, void *statBuf);

/// csops：查询进程代码签名状态
int aegis_csops(uint32_t pid, uint32_t ops, void *useraddr, uint32_t usersize);

/// CS_OPS_STATUS
#define AEGIS_CS_OPS_STATUS 0

/// csflags 常量
#define AEGIS_CS_VALID       0x00000001
#define AEGIS_CS_DEBUGGED    0x10000000
#define AEGIS_CS_RESTRICT    0x00000800
#define AEGIS_CS_HARD        0x00000100
#define AEGIS_CS_KILL        0x00000200
#define AEGIS_CS_PLATFORM    0x00000400

/// 读取 kern.bootargs，成功返回 true
bool aegis_read_bootargs(char *buf, size_t bufSize, size_t *outLen);

/// 判断地址是否落在任一已加载映像范围内（用于指针完整性启发式检测）
bool aegis_address_in_image(uintptr_t addr);

/// 统计当前进程 RWX 内存页数量
int aegis_count_rwx_regions(void);

/// 探测本机 TCP 端口是否开放（用于 Frida 27042 检测）
bool aegis_port_open(int port, int timeoutMs);

#endif /* AegisShim_h */
