#include <stdint.h>
#include <seccomp.h>

#if (SCMP_VER_MAJOR < 2) || \
    (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 5) || \
    (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR == 5 && SCMP_VER_MICRO < 1)
#error This package requires libseccomp >= v2.5.1
#endif

typedef enum {
  F_VERBOSE    = 1 << 0,
  F_EXT        = 1 << 1,
  F_DENY_NS    = 1 << 2,
  F_DENY_TTY   = 1 << 3,
  F_DENY_DEVEL = 1 << 4,
  F_MULTIARCH  = 1 << 5,
  F_LINUX32    = 1 << 6,
  F_CAN        = 1 << 7,
  F_BLUETOOTH  = 1 << 8,
} f_filter_opts;

extern void f_println(char *v);
int32_t f_build_filter(int *ret_p, int fd, uint32_t arch, uint32_t multiarch, f_filter_opts opts);