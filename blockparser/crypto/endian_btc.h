// Cross-platform endian helpers for Windows (Microsoft Visual C++) and POSIX (Portable Operating System Interface).
// Header is self-contained and provides htobe*/htole* and be*/le*toh macros used by crypto/common_btc.h.
#pragma once
#include <stdint.h>

#if defined(_MSC_VER) || defined(_WIN32) || defined(WIN32)
  // Windows is little-endian; provide byte-swap intrinsics.
  #include <stdlib.h>  // _byteswap_ushort, _byteswap_ulong, _byteswap_uint64
  #if defined(_MSC_VER)
    #include <intrin.h>
  #endif

  #ifndef htobe16
  #define htobe16(x) _byteswap_ushort((uint16_t)(x))
  #endif
  #ifndef htole16
  #define htole16(x) ((uint16_t)(x))
  #endif
  #ifndef be16toh
  #define be16toh(x) _byteswap_ushort((uint16_t)(x))
  #endif
  #ifndef le16toh
  #define le16toh(x) ((uint16_t)(x))
  #endif

  #ifndef htobe32
  #define htobe32(x) _byteswap_ulong((uint32_t)(x))
  #endif
  #ifndef htole32
  #define htole32(x) ((uint32_t)(x))
  #endif
  #ifndef be32toh
  #define be32toh(x) _byteswap_ulong((uint32_t)(x))
  #endif
  #ifndef le32toh
  #define le32toh(x) ((uint32_t)(x))
  #endif

  #ifndef htobe64
  #define htobe64(x) _byteswap_uint64((uint64_t)(x))
  #endif
  #ifndef htole64
  #define htole64(x) ((uint64_t)(x))
  #endif
  #ifndef be64toh
  #define be64toh(x) _byteswap_uint64((uint64_t)(x))
  #endif
  #ifndef le64toh
  #define le64toh(x) ((uint64_t)(x))
  #endif

#else
  // Non-Windows platforms: use native <endian.h>
  #include <endian.h>
#endif

