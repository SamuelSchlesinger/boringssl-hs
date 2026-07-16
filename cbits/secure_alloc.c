#include "secure_alloc.h"

#include <openssl/mem.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

static size_t round_to_pages(size_t len) {
#if defined(_WIN32)
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  size_t page = (size_t)info.dwPageSize;
#else
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
#endif
  if (len == 0) {
    len = 1;
  }
  return ((len + page - 1) / page) * page;
}

void *bssl_hs_secure_alloc(size_t len) {
  size_t size = round_to_pages(len);
#if defined(_WIN32)
  /* MEM_COMMIT memory is zero-initialized by the OS. */
  void *ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (ptr == NULL) {
    return NULL;
  }
  /* Best effort: keeps the pages out of the pagefile. The default working
   * set minimum makes this fail once many pages are locked; proceed
   * unlocked in that case. */
  (void)VirtualLock(ptr, size);
#else
  void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ptr == MAP_FAILED) {
    return NULL;
  }
  /* Best effort: RLIMIT_MEMLOCK may be as low as 64 KiB on older systems. */
  (void)mlock(ptr, size);
#if defined(MADV_DONTDUMP)
  (void)madvise(ptr, size, MADV_DONTDUMP);
#endif
#endif
  return ptr;
}

void bssl_hs_secure_free(void *ptr, size_t len) {
  if (ptr == NULL) {
    return;
  }
  size_t size = round_to_pages(len);
  /* Cleanse the whole mapped region, not just |len|, so padding written by
   * accident is covered too. */
  OPENSSL_cleanse(ptr, size);
#if defined(_WIN32)
  (void)VirtualUnlock(ptr, size);
  VirtualFree(ptr, 0, MEM_RELEASE);
#else
  (void)munlock(ptr, size);
  (void)munmap(ptr, size);
#endif
}
