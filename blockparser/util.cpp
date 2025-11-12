
#include <string>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <algorithm>
#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <util.h>
#include <timer.h>
// Windows/MSVC vs POSIX alloca
#if defined(_MSC_VER)
#include <malloc.h>
#ifndef alloca
#define alloca _alloca
#endif
#else
#include <alloca.h>
#endif
#include <common.h>
#include <errlog.h>
#include <rmd160.h>
#include <sha256.h>
#include <opcodes.h>

const uint8_t hexDigits[] = "0123456789abcdef";
const uint8_t b58Digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

template<> uint8_t *PagedAllocator<Block>::pool = 0;
template<> uint8_t *PagedAllocator<Block>::poolEnd = 0;

template<> uint8_t *PagedAllocator<uint256_t>::pool = 0;
template<> uint8_t *PagedAllocator<uint256_t>::poolEnd = 0;

template<> uint8_t *PagedAllocator<uint160_t>::pool = 0;
template<> uint8_t *PagedAllocator<uint160_t>::poolEnd = 0;

template<> uint8_t *PagedAllocator<Chunk>::pool = 0;
template<> uint8_t *PagedAllocator<Chunk>::poolEnd = 0;

size_t ScriptAddressKeyHasher::operator()(const ScriptAddressKey &key) const
{
### codex/locate-files-for-blk-processing-and-validation-7l8uwa
    uint64_t hash = key.programLen;
###
    uint64_t hash = (uint64_t)key.type;
    hash = (hash << 8) ^ key.addrType;
    hash = (hash << 8) ^ key.programLen;
### master
    for(uint8_t i = 0; i < key.programLen; ++i) {
        hash = (hash * 1315423911u) ^ key.program[i];
    }
    return (size_t)hash;
}

ScriptAddressKey makeScriptAddressKey(const ScriptAddress &addr)
{
    ScriptAddressKey key;
    key.type = (addr.type < 0) ? ScriptAddressKey::UNKNOWN : (uint8_t)addr.type;
    key.addrType = (addr.type < 0) ? ScriptAddressKey::UNKNOWN : addr.addrType;
    key.programLen = addr.programLen;
    key.program.fill(0);
    for(uint8_t i = 0; i < addr.programLen && i < key.program.size(); ++i) {
        key.program[i] = addr.program[i];
    }
    return key;
}

ScriptAddress scriptAddressFromKey(const ScriptAddressKey &key)
{
    ScriptAddress addr;
### codex/locate-files-for-blk-processing-and-validation-7l8uwa
    addr.type = (key.type == ScriptAddressKey::UNKNOWN) ? -1 : key.type;
###
    addr.type = (key.type == 0xff) ? -1 : key.type;
### master
    addr.addrType = key.addrType;
    addr.programLen = key.programLen;
    for(uint8_t i = 0; i < key.programLen && i < addr.program.size(); ++i) {
        addr.program[i] = key.program[i];
    }
    return addr;
}

time_t timegmCompat(struct tm *utc)
{
#if defined(_WIN32)
    return _mkgmtime(utc);
#else
    return timegm(utc);
#endif
}

bool parseTimeString(const char *value, int64_t &out)
{
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if(6!=sscanf(value, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second)) {
        return false;
    }
    if(year<1970 || month<1 || 12<month || day<1 || 31<day || hour<0 || 23<hour || minute<0 || 59<minute || second<0 || 59<second) {
        return false;
    }

    struct tm utc;
    memset(&utc, 0, sizeof(utc));
    utc.tm_year = year - 1900;
    utc.tm_mon = month - 1;
    utc.tm_mday = day;
    utc.tm_hour = hour;
    utc.tm_min = minute;
    utc.tm_sec = second;
    utc.tm_isdst = 0;

    time_t converted = timegmCompat(&utc);
    if(converted<0) {
        return false;
    }
    out = (int64_t)converted;
    return true;
}

void toHex(
          uint8_t *dst,     // 2*size +1
    const uint8_t *src,     // size
    size_t        size,
    bool          rev
) {
    int incr = 1;
    const uint8_t *p = src;
    const uint8_t *e = size + src;
    if(rev) {
        p = e-1;
        e = src-1;
        incr = -1;
    }
    
    while(likely(p!=e)) {
        uint8_t c = p[0];
        dst[0] = hexDigits[c>>4];
        dst[1] = hexDigits[c&0xF];
        p += incr;
        dst += 2;
    }
    dst[0] = 0;
}

void showHex(
    const uint8_t *p,
    size_t        size,
    bool          rev
) {
    uint8_t* buf = (uint8_t*)alloca(2*size + 1);
    toHex(buf, p, size, rev);
    printf("%s", buf);
}

uint8_t fromHexDigit(
    uint8_t h,
    bool abortOnErr
) {
    if(likely('0'<=h && h<='9')) return      (h - '0');
    if(likely('a'<=h && h<='f')) return 10 + (h - 'a');
    if(likely('A'<=h && h<='F')) return 10 + (h - 'A');
    if(abortOnErr) errFatal("incorrect hex digit %c", h);
    return 0xFF;
}

bool fromHex(
          uint8_t *dst,
    const uint8_t *src,
    size_t        dstSize,
    bool          rev,
    bool          abortOnErr
) {
    int incr = 2;
    uint8_t *end = dstSize + dst;
    if(rev) {
        src += 2*(dstSize-1);
        incr = -2;
    }

    while(likely(dst<end)) {
        uint8_t hi = fromHexDigit(src[0], abortOnErr);
        if(unlikely(0xFF==hi)) return false;

        uint8_t lo = fromHexDigit(src[1], abortOnErr);
        if(unlikely(0xFF==lo)) return false;

        *(dst++) = (hi<<4) + lo;
        src += incr;
    }

    return true;
}

static bool getOpPushData(
    const uint8_t *&p,
    uint64_t &dataSize
) {

    dataSize = 0;
    LOAD(uint8_t, c, p);

    bool isImmediate = (0<c && c<79);
    if(!isImmediate) {
        --p;
        return false;
    }

         if(likely(c<=75)) {                       dataSize = c; }
    else if(likely(76==c)) { LOAD( uint8_t, v, p); dataSize = v; }
    else if(likely(77==c)) { LOAD(uint16_t, v, p); dataSize = v; }
    else if(likely(78==c)) { LOAD(uint32_t, v, p); dataSize = v; }
    if(512*1024<dataSize) {
        return false;
    }

    p += dataSize;
    return true;
}

// This is a tad arbitrary but works well in practice
bool isCommentScript(
    const uint8_t *p,
    size_t scriptSize
) {
    const uint8_t *e = scriptSize + p;
    while(likely(p<e)) {
        LOAD(uint8_t, c, p);
        bool isImmediate = (0<c && c<79);
        if(!isImmediate) {
            if(0x6A!=c) {
                return false;
            }
        } else {

            --p;

            uint64_t dataSize = 0;
            auto ok = getOpPushData(p, dataSize);
            if(!ok) {
                return false;
            }
        }
    }
    return true;
}

struct Compare160 {
    bool operator()(
        const uint160_t &a,
        const uint160_t &b
    ) const {
        auto as = a.v;
        auto bs = b.v;
        auto ae = kRIPEMD160ByteSize + as;
        while(as<ae) {
            int delta = ((int)*(as++)) - ((int)*(bs++));
            if(delta) {
                return (delta<0);
            }
        }
        return true;
    }
};

static void packMultiSig(
                   uint8_t *pubKeyHash,
    std::vector<uint160_t> &addresses,
                       int m,
                       int n
) {
    std::sort(
        addresses.begin(),
        addresses.end(),
        Compare160()
    );

    std::vector<uint8_t> data;
    data.reserve(2 + kRIPEMD160ByteSize*sizeof(addresses));
    data.push_back((uint8_t)m);
    data.push_back((uint8_t)n);
    for(const auto &addr:addresses) {
        data.insert(
            data.end(),
            addr.v,
            kRIPEMD160ByteSize + addr.v
        );
    }
    rmd160(
        pubKeyHash,
        &(data[0]),
        data.size()
    );
}

// Try to pattern match a multisig
bool isMultiSig(
    int &_m,
    int &_n,
    std::vector<uint160_t> &addresses,
    const uint8_t *p,
    size_t scriptSize
) {

    auto e = scriptSize + p;
    if(scriptSize<=5) {
        return false;
    }

    auto m = (*(p++) - 0x50);             // OP_1 ... OP-16
    auto isMValid = (1<=m && m<=16);
    if(!isMValid) {
        return false;
    }

    int count = 0;
    while(1) {
        uint64_t dataSize = 0;
        auto ok = getOpPushData(p, dataSize);
        if(e<=p) {
            return false;
        }
        if(!ok) {
            break;
        }

        uint160_t addr;
        auto sz = sizeof(addr);
        memcpy(addr.v, p-sz, sz);
        addresses.push_back(addr);
        ++count;
    }

    auto n = (*(p++) - 0x50);             // OP_1 ... OP-16
    auto isNValid = (1<=n && n<=16);
    if(!isNValid || n!=count) {
        return false;
    }

    auto lastOp = *(p++);
    bool ok = (0xAE==lastOp) &&          // OP_CHECKMULTISIG
              (m<=n)         &&
              (p==e);
    if(ok) {
        _m = m;
        _n = n;
    }
    return ok;
}

void showScript(
    const uint8_t *p,
    size_t        scriptSize,
    const char    *header,
    const char    *indent,
    bool          showAscii
) {
    bool first = true;
    const uint8_t *e = scriptSize + p;
    indent = indent ? indent : "";
    while(likely(p<e)) {
        LOAD(uint8_t, c, p);
        bool isImmediate = (0<c && c<79) ;
        if(!isImmediate) {
            printf(
                "    %s0x%02X %s%s\n",
                indent,
                c,
                getOpcodeName(c),
                (first && header) ? header : ""
            );
        } else {
            uint64_t dataSize = 0;
                 if(likely(c<=75)) {                       dataSize = c; }
            else if(likely(76==c)) { LOAD( uint8_t, v, p); dataSize = v; }
            else if(likely(77==c)) { LOAD(uint16_t, v, p); dataSize = v; }
            else if(likely(78==c)) { LOAD(uint32_t, v, p); dataSize = v; }

            printf("         %sOP_PUSHDATA(%" PRIu64 ", 0x", indent, dataSize);
            if(512*1024<dataSize) {
                printf(" -- dataSize is weird, likely an invalid script -- bailing.\n");
                return;
            } else {
                showHex(p, dataSize, false);
                printf(
                    ")%s\n",
                    (first && header) ? header : ""
                );
                if(showAscii) {
                    printf("ascii version of data:\n");
                    canonicalHexDump(p, dataSize, "");
                    printf("\n");
                }
                p += dataSize;
            }
        }
        first = false;
    }
}

bool compressPublicKey(
          uint8_t *result,          // 33 bytes
    const uint8_t *decompressedKey  // 65 bytes
) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if(!key) {
        errFatal("EC_KEY_new_by_curve_name failed");
        return false;
    }

    EC_KEY *r = o2i_ECPublicKey(&key, &decompressedKey, 65);
    if(!r) {
        //warning("o2i_ECPublicKey failed");
        EC_KEY_free(key);
        return false;
    }

    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    size_t size = i2o_ECPublicKey(key, &result);
    EC_KEY_free(key);

    if(33!=size) {
        errFatal("i2o_ECPublicKey failed");
        return false;
    }

    return true;
}

bool decompressPublicKey(
          uint8_t *result,          // 65 bytes
    const uint8_t *compressedKey    // 33 bytes
) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if(!key) {
        errFatal("EC_KEY_new_by_curve_name failed");
        return false;
    }

    EC_KEY *r = o2i_ECPublicKey(&key, &compressedKey, 33);
    if(!r) {
        //warning("o2i_ECPublicKey failed");
        EC_KEY_free(key);
        return false;
    }

    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    size_t size = i2o_ECPublicKey(key, &result);
    EC_KEY_free(key);

    if(65!=size) {
        errFatal("i2o_ECPublicKey failed");
        return false;
    }

    return true;
}

int solveOutputScript(
    ScriptAddress &addr,
    const uint8_t *script,
    uint64_t       scriptSize
) {
    addr.reset();

    if(unlikely(0==scriptSize)) {
        return -1;
    }

    // The most common output script type that pays to hash160(pubKey)
    if(
        likely(
            0x76==script[0]              &&  // OP_DUP
            0xA9==script[1]              &&  // OP_HASH160
              20==script[2]              &&  // OP_PUSHDATA(20)
            0x88==script[scriptSize-2]   &&  // OP_EQUALVERIFY
            0xAC==script[scriptSize-1]   &&  // OP_CHECKSIG
              25==scriptSize
        )
    ) {
        addr.type = 0;
        addr.addrType = 0;
        addr.programLen = kRIPEMD160ByteSize;
        memcpy(addr.program.data(), 3+script, kRIPEMD160ByteSize);
        return addr.type;
    }

    // Output script commonly found in block reward TX, that pays to an explicit pubKey
    if(
        likely(
              65==script[0]             &&  // OP_PUSHDATA(65)
            0xAC==script[scriptSize-1]  &&  // OP_CHECKSIG
              67==scriptSize
        )
    ) {
        uint256_t sha;
        sha256(sha.v, 1+script, 65);
        rmd160(addr.program.data(), sha.v, kSHA256ByteSize);
        addr.type = 1;
        addr.addrType = 0;
        addr.programLen = kRIPEMD160ByteSize;
        return addr.type;
    }

    // A rather unusual output script that pays to explicit compressed pubKey
    if(
        likely(
              33==script[0]            &&  // OP_PUSHDATA(33)
            0xAC==script[scriptSize-1] &&  // OP_CHECKSIG
              35==scriptSize
        )
    ) {
        uint256_t sha;
        sha256(sha.v, 1+script, 33);
        rmd160(addr.program.data(), sha.v, kSHA256ByteSize);
        addr.type = 2;
        addr.addrType = 0;
        addr.programLen = kRIPEMD160ByteSize;
        return addr.type;
    }

    // A modern output script type, that pays to hash160(script)
    if(
        likely(
            0xA9==script[0]             &&  // OP_HASH160
              20==script[1]             &&  // OP_PUSHDATA(20)
            0x87==script[scriptSize-1]  &&  // OP_EQUAL
              23==scriptSize
        )
    ) {
        addr.type = 3;
        addr.addrType = 5;
        addr.programLen = kRIPEMD160ByteSize;
        memcpy(addr.program.data(), 2+script, kRIPEMD160ByteSize);
        return addr.type;
    }

    int m = 0;
    int n = 0;
    std::vector<uint160_t> addresses;
    if(
        isMultiSig(
            m,
            n,
            addresses,
            script,
            scriptSize
        )
    ) {
        addr.type = 4;
        addr.addrType = 8;
        addr.programLen = kRIPEMD160ByteSize;
        packMultiSig(addr.program.data(), addresses, m, n);
        return addr.type;
    }

    // Witness program: OP_n <program>
    if(scriptSize >= 4 && scriptSize <= 42) {
        uint8_t version = 0xff;
        if(0x00 == script[0]) {
            version = 0;
        } else if(0x51 <= script[0] && script[0] <= 0x60) {
            version = script[0] - 0x50;
        }

        if(version != 0xff) {
            uint8_t programLen = script[1];
            if(programLen + 2 == scriptSize && programLen >= 2 && programLen <= 40) {
                if(version == 0 && !(programLen == 20 || programLen == 32)) {
                    // invalid witness v0 length
                    return -1;
                }

                addr.addrType = 0x80 | version;
                addr.programLen = programLen;
                memcpy(addr.program.data(), script + 2, programLen);

                if(version == 0 && programLen == 20) {
                    addr.type = 5; // P2WPKH
                } else if(version == 0 && programLen == 32) {
                    addr.type = 6; // P2WSH
                } else if(version == 1 && programLen == 32) {
                    addr.type = 7; // Taproot
                } else {
                    addr.type = 8; // Generic witness program
                }
                return addr.type;
            }
        }
    }

    // Broken output scripts that were created by p2pool for a while
    if(
        0x73==script[0] &&                  // OP_IFDUP
        0x63==script[1] &&                  // OP_IF
        0x72==script[2] &&                  // OP_2SWAP
        0x69==script[3] &&                  // OP_VERIFY
        0x70==script[4] &&                  // OP_2OVER
        0x74==script[5]                     // OP_DEPTH
    ) {
        return -2;
    }

    // A non-functional "comment" script
    if(isCommentScript(script, scriptSize)) {
        return -3;
    }

    // A challenge: anyone who can find X such that 0==RIPEMD160(X) stands to earn a bunch of coins
    if(
        0x76==script[0] &&                  // OP_DUP
        0xA9==script[1] &&                  // OP_HASH160
        0x00==script[2] &&                  // OP_0
        0x88==script[3] &&                  // OP_EQUALVERIFY
        0xAC==script[4]                     // OP_CHECKSIG
    ) {
        return -4;
    }

    return -1;
}

const uint8_t *loadKeyHash(
    const uint8_t *hexHash
) {
    static bool loaded = false;
    static uint8_t hash[kRIPEMD160ByteSize];
    const char *someHexHash = "0568015a9facccfd09d70d409b6fc1a5546cecc6"; // 1VayNert3x1KzbpzMGt2qdqrAThiRovi8 deepbit's very large address

    if(unlikely(!loaded))
    {
        if(0==hexHash)
            hexHash = reinterpret_cast<const uint8_t *>(someHexHash);

        if((2*kRIPEMD160ByteSize)!=strlen((const char *)hexHash))
            errFatal("specified hash has wrong length");

        fromHex(hash, hexHash, sizeof(hash), false);
        loaded = true;
    }

    return hash;
}

uint8_t fromB58Digit(
    uint8_t digit,
       bool abortOnErr
) {
    if('1'<=digit && digit<='9') return (digit - '1') +   0;
    if('A'<=digit && digit<='H') return (digit - 'A') +   9;
    if('J'<=digit && digit<='N') return (digit - 'J') +  17;
    if('P'<=digit && digit<='Z') return (digit - 'P') +  22;
    if('a'<=digit && digit<='k') return (digit - 'a') +  33;
    if('m'<=digit && digit<='z') return (digit - 'm') +  44;
    if(abortOnErr) errFatal("incorrect base58 digit %c", digit);
    return 0xff;
}

static int getCoinType() {
    return
        #if defined(PROTOSHARES)
            56
        #endif

        #if defined(DARKCOIN)
            48 + 28
        #endif

        #if defined(PAYCON)
            55
        #endif

        #if defined(LITECOIN)
            48
        #endif

        #if defined(BITCOIN)
            0
        #endif
        
        #if defined(TESTNET3)
            0
        #endif        
        
        #if defined(FEDORACOIN)
            33
        #endif

        #if defined(PEERCOIN)
            48 + 7
        #endif

        #if defined(CLAM)
            137
        #endif

        #if defined(JUMBUCKS)
            43
        #endif

        #if defined(DOGECOIN)
            30
        #endif

        #if defined(MYRIADCOIN)
            50
        #endif
                
        #if defined(UNOBTANIUM)
            130
        #endif
    ;
}

bool addrToHash160(
          uint8_t *hash160,
    const uint8_t *addr,
             bool checkHash,
             bool verbose
) {
    static BIGNUM *sum = 0;
    static BN_CTX *ctx = 0;
    if(unlikely(!ctx)) {
        ctx = BN_CTX_new();
        sum = BN_new();
    }

    BN_zero(sum);
    while(1) {
        uint8_t c = *(addr++);
        if(unlikely(0==c)) break;

        uint8_t dg = fromB58Digit(c);
        BN_mul_word(sum, 58);
        BN_add_word(sum, dg);
    }

    uint8_t buf[4 + 2 + kRIPEMD160ByteSize + 4];
    size_t size = BN_bn2mpi(sum, 0);
    if(sizeof(buf)<size) {
        warning(
            "BN_bn2mpi returned weird buffer size %d, expected %d\n",
            (int)size,
            (int)sizeof(buf)
        );
        return false;
    }

    BN_bn2mpi(sum, buf);

    uint32_t recordedSize = 
        (buf[0]<<24)    |
        (buf[1]<<16)    |
        (buf[2]<< 8)    |
        (buf[3]<< 0)
    ;
    if(size!=(4+recordedSize)) {
        warning(
            "BN_bn2mpi returned bignum size %d, expected %d\n",
            (int)recordedSize,
            (int)size-4
        );
        return false;
    }

    uint8_t *bigNumEnd;
    uint8_t *dataEnd = size + buf;
    uint8_t *bigNumStart = 4 + buf;
    uint8_t *checkSumStart = bigNumEnd = (-4 + dataEnd);
    while(0==bigNumStart[0] && bigNumStart<checkSumStart) ++bigNumStart;

    ptrdiff_t bigNumSize = bigNumEnd - bigNumStart;
    ptrdiff_t padSize = kRIPEMD160ByteSize - bigNumSize;
    if(0<padSize) {
        if(0<bigNumSize) {
            memcpy(padSize + hash160, bigNumStart, bigNumSize);
        }
        memset(hash160, 0, padSize);
    } else {
        memcpy(hash160, bigNumStart - padSize, kRIPEMD160ByteSize);
    }

    bool hashOK = true;
    if(checkHash) {

        uint8_t data[1+kRIPEMD160ByteSize];
        memcpy(1+data, hash160, kRIPEMD160ByteSize);
        data[0] = getCoinType();

        uint8_t sha[kSHA256ByteSize];
        sha256Twice(sha, data, 1+kRIPEMD160ByteSize);

        hashOK =
            sha[0]==checkSumStart[0]  &&
            sha[1]==checkSumStart[1]  &&
            sha[2]==checkSumStart[2]  &&
            sha[3]==checkSumStart[3];

        if(!hashOK) {
            warning(
                "checksum of address %s failed. Expected 0x%x%x%x%x, got 0x%x%x%x%x.",
                addr,
                checkSumStart[0],
                checkSumStart[1],
                checkSumStart[2],
                checkSumStart[3],
                sha[0],
                sha[1],
                sha[2],
                sha[3]
            );
        }
    }

    return hashOK;
}

void hash160ToAddr(
          uint8_t *addr,    // 36 bytes is safe, even with pad on
    const uint8_t *hash160,
             bool pad,
          uint8_t type
) {
    uint8_t buf[4 + 2 + kRIPEMD160ByteSize + kSHA256ByteSize];
    const uint32_t size = 4 + 2 + kRIPEMD160ByteSize;
    memcpy(4 + 2 + buf, hash160, kRIPEMD160ByteSize);
    buf[ 0] = (size>>24) & 0xff;
    buf[ 1] = (size>>16) & 0xff;
    buf[ 2] = (size>> 8) & 0xff;
    buf[ 3] = (size>> 0) & 0xff;
    buf[ 4] = 0;
    buf[ 5] = getCoinType() + type;
    sha256Twice(
        4 + 2 + kRIPEMD160ByteSize + buf,
        4 + 1 + buf,
        1 + kRIPEMD160ByteSize
    );

    static BIGNUM *b58 = 0;
    static BIGNUM *num = 0;
    static BIGNUM *div = 0;
    static BIGNUM *rem = 0;
    static BN_CTX *ctx = 0;

    if(!ctx) {
        ctx = BN_CTX_new();

        b58 = BN_new();
        num = BN_new();
        div = BN_new();
        rem = BN_new();
        BN_set_word(b58, 58);
    }

    BN_mpi2bn(buf, 4+size, num);

    uint8_t *p = addr;
    while(!BN_is_zero(num)) {
        int r = BN_div(div, rem, num, b58, ctx);
        if(!r) errFatal("BN_div failed");
        BN_copy(num, div);

        uint32_t digit = BN_get_word(rem);
        *(p++) = b58Digits[digit];
    }

    const uint8_t *a =                          (5+buf);
    const uint8_t *e = 1 + kRIPEMD160ByteSize + (5+buf);
    while(a<e && 0==a[0]) {
        *(p++) = b58Digits[0];
        ++a;
    }
    *p = 0;

    auto l = addr;
    auto r = p - 1;
    while(l<r) {
        uint8_t a = *l;
        uint8_t b = *r;
        *(l++) = b;
        *(r--) = a;
    }

    if(pad) {
        auto sz = p - addr;
        auto delta = 34 - sz;
        if(0<delta) {
            while(delta--) {
                *(p++) = ' ';
            }
            *(p++) = 0;
        }
    }
}

static const char kBech32Charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32Polymod(const std::vector<uint8_t> &values)
{
    static const uint32_t generators[5] = {
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    };

    uint32_t chk = 1;
    for(uint8_t value : values) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ value;
        for(int i = 0; i < 5; ++i) {
            if((top >> i) & 1) {
                chk ^= generators[i];
            }
        }
    }
    return chk;
}

static void bech32HrpExpand(const std::string &hrp, std::vector<uint8_t> &out)
{
    out.clear();
    out.reserve(hrp.size() * 2 + 1);
    for(char c : hrp) {
        out.push_back(static_cast<uint8_t>(c >> 5));
    }
    out.push_back(0);
    for(char c : hrp) {
        out.push_back(static_cast<uint8_t>(c & 31));
    }
}

static std::vector<uint8_t> bech32CreateChecksum(
    const std::string &hrp,
    const std::vector<uint8_t> &values,
    bool bech32m
)
{
    std::vector<uint8_t> hrpExpand;
    bech32HrpExpand(hrp, hrpExpand);

    std::vector<uint8_t> combined = hrpExpand;
    combined.reserve(hrpExpand.size() + values.size() + 6);
    combined.insert(combined.end(), values.begin(), values.end());
    combined.insert(combined.end(), 6, 0);

    uint32_t polymod = bech32Polymod(combined) ^ (bech32m ? 0x2bc830a3 : 1);

    std::vector<uint8_t> checksum(6);
    for(size_t i = 0; i < 6; ++i) {
        checksum[i] = (polymod >> (5 * (5 - i))) & 31;
    }
    return checksum;
}

static bool convertBits(
    std::vector<uint8_t> &out,
    const std::vector<uint8_t> &in,
    int fromBits,
    int toBits,
    bool pad
) {
    int acc = 0;
    int bits = 0;
    const int maxv = (1 << toBits) - 1;
    const int maxAcc = (1 << (fromBits + toBits - 1)) - 1;
    out.clear();
    for(uint8_t value : in) {
        if((value >> fromBits)) {
            return false;
        }
        acc = ((acc << fromBits) | value) & maxAcc;
        bits += fromBits;
        while(bits >= toBits) {
            bits -= toBits;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if(pad) {
        if(bits) {
            out.push_back((acc << (toBits - bits)) & maxv);
        }
    } else {
        if(bits >= fromBits) {
            return false;
        }
        if(((acc << (toBits - bits)) & maxv)) {
            return false;
        }
    }
    return true;
}

static int bech32CharValue(char c)
{
    const char *p = strchr(kBech32Charset, c);
    if(!p) {
        return -1;
    }
    return p - kBech32Charset;
}

static bool decodeBech32(
    const std::string &input,
    std::string &hrp,
    std::vector<uint8_t> &data,
    bool &isBech32m
) {
    if(input.size() < 8 || input.size() > 90) {
        return false;
    }

    bool hasLower = false;
    bool hasUpper = false;
    for(char c : input) {
        if(c >= 'a' && c <= 'z') hasLower = true;
        if(c >= 'A' && c <= 'Z') hasUpper = true;
        if(c < 33 || c > 126) {
            return false;
        }
    }
    if(hasLower && hasUpper) {
        return false;
    }

    std::string copy = input;
    std::transform(copy.begin(), copy.end(), copy.begin(), ::tolower);
    auto pos = copy.rfind('1');
    if(pos == std::string::npos || pos < 1 || pos + 7 > copy.size()) {
        return false;
    }

    hrp = copy.substr(0, pos);
    data.clear();
    data.reserve(copy.size() - pos - 1);
    for(size_t i = pos + 1; i < copy.size(); ++i) {
        int v = bech32CharValue(copy[i]);
        if(v < 0) {
            return false;
        }
        data.push_back(static_cast<uint8_t>(v));
    }

    if(data.size() < 6) {
        return false;
    }

    std::vector<uint8_t> hrpExpand;
    bech32HrpExpand(hrp, hrpExpand);

    std::vector<uint8_t> values = hrpExpand;
    values.insert(values.end(), data.begin(), data.end());

    uint32_t polymod = bech32Polymod(values);
    if(polymod == 1) {
        isBech32m = false;
    } else if(polymod == 0x2bc830a3) {
        isBech32m = true;
    } else {
        return false;
    }

    data.resize(data.size() - 6);
    return true;
}

static const char *getWitnessHRP()
{
#if defined(BITCOIN)
    return "bc";
#elif defined(TESTNET3)
    return "tb";
#else
    return "";
#endif
}

static bool encodeWitnessAddress(const ScriptAddress &addr, std::string &output)
{
    if((addr.addrType & 0x80) == 0) {
        return false;
    }

    const char *hrpC = getWitnessHRP();
    if(!hrpC[0]) {
        return false;
    }
    std::string hrp(hrpC);

    uint8_t version = addr.addrType & 0x7f;
    if(version > 16) {
        return false;
    }

    if(addr.programLen < 2 || addr.programLen > 40) {
        return false;
    }
    if(version == 0 && !(addr.programLen == 20 || addr.programLen == 32)) {
        return false;
    }

    std::vector<uint8_t> program(addr.program.begin(), addr.program.begin() + addr.programLen);
    std::vector<uint8_t> converted;
    if(!convertBits(converted, program, 8, 5, true)) {
        return false;
    }

    std::vector<uint8_t> payload;
    payload.reserve(1 + converted.size());
    payload.push_back(version);
    payload.insert(payload.end(), converted.begin(), converted.end());

    bool bech32m = (version > 0);
    std::vector<uint8_t> checksum = bech32CreateChecksum(hrp, payload, bech32m);
    payload.insert(payload.end(), checksum.begin(), checksum.end());

    output.assign(hrp);
    output.push_back('1');
    for(uint8_t v : payload) {
        if(v >= 32) {
            return false;
        }
        output.push_back(kBech32Charset[v]);
    }
    return true;
}

static bool decodeWitnessAddress(
    const std::string &input,
    ScriptAddressKey &key
) {
    std::string hrp;
    std::vector<uint8_t> data;
    bool bech32m = false;
    if(!decodeBech32(input, hrp, data, bech32m)) {
        return false;
    }

    const char *expected = getWitnessHRP();
    if(!expected[0] || hrp != expected) {
        return false;
    }

    if(data.empty() || data[0] > 16) {
        return false;
    }
    uint8_t version = data[0];
    std::vector<uint8_t> program5(data.begin() + 1, data.end());
    std::vector<uint8_t> program8;
    if(!convertBits(program8, program5, 5, 8, false)) {
        return false;
    }
    if(program8.size() < 2 || program8.size() > 40) {
        return false;
    }
    if(version == 0 && !(program8.size() == 20 || program8.size() == 32)) {
        return false;
    }
    if(version == 0 && bech32m) {
        return false;
    }
    if(version > 0 && !bech32m) {
        return false;
    }

    key.program.fill(0);
    key.programLen = static_cast<uint8_t>(program8.size());
    for(size_t i = 0; i < program8.size(); ++i) {
        key.program[i] = program8[i];
    }
    key.addrType = 0x80 | version;
    if(version == 0 && program8.size() == 20) {
        key.type = 5;
    } else if(version == 0 && program8.size() == 32) {
        key.type = 6;
    } else if(version == 1 && program8.size() == 32) {
        key.type = 7;
    } else {
        key.type = 8;
    }
    return true;
}

static bool decodeBase58Check(
    const std::string &input,
    std::vector<uint8_t> &decoded
) {
    decoded.clear();
    decoded.reserve(input.size());

    std::vector<uint8_t> tmp;
    tmp.reserve(input.size());

    for(char c : input) {
        uint8_t value = fromB58Digit(static_cast<uint8_t>(c), false);
        if(value == 0xff) {
            return false;
        }
        int carry = value;
        for(size_t j = 0; j < tmp.size(); ++j) {
            int x = tmp[j] * 58 + carry;
            tmp[j] = x & 0xff;
            carry = x >> 8;
        }
        while(carry > 0) {
            tmp.push_back(carry & 0xff);
            carry >>= 8;
        }
    }

    int leading = 0;
    for(char c : input) {
        if(c == '1') {
            ++leading;
        } else {
            break;
        }
    }

    decoded.assign(leading, 0);
    for(auto it = tmp.rbegin(); it != tmp.rend(); ++it) {
        decoded.push_back(*it);
    }

    if(decoded.size() < 4) {
        return false;
###<<<<<<< codex/locate-files-for-blk-processing-and-validation-7l8uwa
    }

    uint8_t check[kSHA256ByteSize];
    sha256Twice(check, &decoded[0], decoded.size() - 4);
    if(
        check[0] != decoded[decoded.size()-4] ||
        check[1] != decoded[decoded.size()-3] ||
        check[2] != decoded[decoded.size()-2] ||
        check[3] != decoded[decoded.size()-1]
    ) {
        return false;
    }

###=======
    }

    uint8_t check[kSHA256ByteSize];
    sha256Twice(check, &decoded[0], decoded.size() - 4);
    if(
        check[0] != decoded[decoded.size()-4] ||
        check[1] != decoded[decoded.size()-3] ||
        check[2] != decoded[decoded.size()-2] ||
        check[3] != decoded[decoded.size()-1]
    ) {
        return false;
    }

###>>>>>>> master
    decoded.resize(decoded.size() - 4);
    return true;
}

static bool decodeLegacyAddress(
    const std::string &input,
    ScriptAddressKey &key
) {
    std::vector<uint8_t> decoded;
    if(!decodeBase58Check(input, decoded)) {
        return false;
    }
    if(decoded.size() != (1 + kRIPEMD160ByteSize)) {
        return false;
    }

    uint8_t version = decoded[0];
    key.program.fill(0);
    key.programLen = kRIPEMD160ByteSize;
    memcpy(key.program.data(), &decoded[1], kRIPEMD160ByteSize);
    key.addrType = version - getCoinType();
    if(key.addrType == 5) {
        key.type = 3;
    } else {
        key.type = 0;
    }
    return true;
}

static bool parseAddressString(
    const std::string &input,
    ScriptAddressKey &key,
    bool verbose
) {
    std::string trimmed = input;
    while(!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r')) {
        trimmed.pop_back();
    }

### codex/locate-files-for-blk-processing-and-validation-7l8uwa
    if(trimmed.size() == 2 * kRIPEMD160ByteSize || trimmed.size() == 2 * kSHA256ByteSize) {
        const size_t expectedLen = (trimmed.size() == 2 * kRIPEMD160ByteSize)
            ? kRIPEMD160ByteSize
            : kSHA256ByteSize;

        uint8_t hashBuf[kSHA256ByteSize];

        if(fromHex(hashBuf, reinterpret_cast<const uint8_t*>(trimmed.c_str()), expectedLen, false, false)) {
            key.program.fill(0);
            key.programLen = expectedLen;
            memcpy(key.program.data(), hashBuf, expectedLen);
            key.addrType = ScriptAddressKey::UNKNOWN;
            key.type = ScriptAddressKey::UNKNOWN;
###
    if(trimmed.size() == 2 * kRIPEMD160ByteSize) {
        uint8_t hash[kRIPEMD160ByteSize];
        if(fromHex(hash, reinterpret_cast<const uint8_t*>(trimmed.c_str()), kRIPEMD160ByteSize, false, false)) {
            key.program.fill(0);
            key.programLen = kRIPEMD160ByteSize;
            memcpy(key.program.data(), hash, kRIPEMD160ByteSize);
            key.addrType = 0;
            key.type = 0;
### master
            return true;
        }
    }

    if(decodeWitnessAddress(trimmed, key)) {
        return true;
    }

    if(decodeLegacyAddress(trimmed, key)) {
        return true;
    }

    if(verbose) {
        warning("%s is not a recognized address", trimmed.c_str());
    }
    return false;
}

void loadKeyList(
    std::vector<ScriptAddressKey> &result,
    const char *str,
    bool verbose
) {
    bool isFile = (
        'f'==str[0] &&
        'i'==str[1] &&
        'l'==str[2] &&
        'e'==str[3] &&
        ':'==str[4]
    );
    if(!isFile) {
        ScriptAddressKey key;
        if(parseAddressString(str, key, true)) {
            result.push_back(key);
        }
        return;
    }

    const char *fileName = 5+str;
    bool isStdIn = ('-'==fileName[0] && 0==fileName[1]);
    FILE *f = isStdIn ? stdin : fopen(fileName, "r");
    if(!f) {
        warning("couldn't open %s for reading\n", fileName);
        return;
    }

    size_t found = 0;
    size_t lineCount = 0;
    double start = Timer::usecs();
    while(1) {

        char buf[1024];
        char *r = fgets(buf, sizeof(buf), f);
        if(r==0) break;
        ++lineCount;

        size_t sz = strlen(buf);
        if(0 < sz && '\n'==buf[sz-1]) buf[sz-1] = 0;

        ScriptAddressKey key;
        bool ok = parseAddressString(buf, key, verbose);
        if(ok) {
            result.push_back(key);
            ++found;
        }
    }
    fclose(f);

    double elapsed = (Timer::usecs() - start)*1e-6;
    info(
        "file %s loaded in %.2f secs, found %d addresses",
        fileName,
        elapsed,
        (int)found
    );
}

void loadHash256List(
    std::vector<uint256_t> &result,
    const char *str,
    bool verbose
) {
    bool isFile = (
        'f'==str[0] &&
        'i'==str[1] &&
        'l'==str[2] &&
        'e'==str[3] &&
        ':'==str[4]
    );

    if(!isFile) {

        size_t sz = strlen(str);
        if(2*kSHA256ByteSize!=sz) errFatal("%s is not a valid TX hash", str);

        uint256_t h256;
        fromHex(h256.v, (const uint8_t *)str);
        result.push_back(h256);
        return;
    }

    const char *fileName = 5+str;
    bool isStdIn = ('-'==fileName[0] && 0==fileName[1]);
    FILE *f = isStdIn ? stdin : fopen(fileName, "r");
    if(!f) {
        warning("couldn't open %s for reading\n", fileName);
        return;
    }

    size_t lineCount = 0;
    while(1) {

        char buf[1024];
        char *r = fgets(buf, sizeof(buf), f);
        if(r==0) break;
        ++lineCount;

        size_t sz = strlen(buf);
        if(2*kSHA256ByteSize<=sz) {

            uint256_t h256;
            bool ok = fromHex(h256.v, (const uint8_t *)buf, kSHA256ByteSize, true, false);
            if(ok)
                result.push_back(h256);
            else if(verbose) {
                warning(
                    "in file %s, line %d, %s is not a valid TX hash\n",
                    fileName,
                    lineCount,
                    buf
                );
            }
        }

    }
    fclose(f);
}

std::string pr128(
    const uint128_t &y
) {
    static char result[1024];
    char *p = 1023+result;
    *(p--) = 0;

    auto x = y;
    while(1) {
        *(p--) = (char)((x % 10) + '0');
        if(unlikely(0==x)) break;
        x /= 10;
    }
    ++p;

    return std::string(p[0]!='0' ? p : (1022+result==p) ? p : p+1);
}

std::string formatAddress(const ScriptAddress &addr, bool pad)
{
    if(!addr.valid()) {
        return std::string();
    }

    if((addr.addrType & 0x80) == 0 && addr.programLen == kRIPEMD160ByteSize) {
        uint8_t buffer[128];
        hash160ToAddr(buffer, addr.program.data(), pad, addr.addrType);
        return std::string(reinterpret_cast<char*>(buffer));
    }

    if(addr.addrType & 0x80) {
        std::string bech32;
        if(encodeWitnessAddress(addr, bech32)) {
            if(pad) {
                const size_t minWidth = std::max<size_t>(bech32.size(), 34);
                if(bech32.size() < minWidth) {
                    bech32.append(minWidth - bech32.size(), ' ');
                }
            }
            return bech32;
        }
    }

    uint8_t hexBuf[2 * kSHA256ByteSize + 1];
    toHex(hexBuf, addr.program.data(), addr.programLen, false);

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "script[%u]:%s", addr.type, hexBuf);

    std::string formatted(tmp);
    if(pad) {
        const size_t minWidth = 34;
        if(formatted.size() < minWidth) {
            formatted.append(minWidth - formatted.size(), ' ');
        }
    }
    return formatted;
}

void showFullAddr(
    const ScriptAddress &addr,
    bool both
) {
    if(!addr.valid()) {
        if(both) {
            printf("(invalid)");
        }
        return;
    }

    uint8_t hexBuf[2 * kSHA256ByteSize + 1];
    if(both) {
        toHex(hexBuf, addr.program.data(), addr.programLen, false);
        printf("%s", hexBuf);
    }

    auto formatted = formatAddress(addr, false);
    if(!formatted.empty()) {
        printf("%s%s", both ? " " : "", formatted.c_str());
    }
}

uint64_t getBaseReward(
    uint64_t h
) {
    static const uint64_t kCoin = 100000000;
    uint64_t reward = (50 * kCoin);
    uint64_t shift = (h/210000);
    reward >>= shift;
    return reward;
}

const char *getInterestingAddr() {

    const char *addr =

    #if defined(BITCOIN)

        "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp"
        
    #elif defined(TESTNET3)
    
        "mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33"

    #elif defined(LITECOIN)

        "LKvTVnkK2rAkJXfgPdkaDRgvEGvazxWS9o"

    #elif defined(DARKCOIN)

        "XnuCAYmAiVHE6Xv3D7Xw685wWzqtcfexLh"

    #elif defined(PEERCOIN)

        "PDH9AeruMUGh2JzYYTpaNtjLAcfGV5LEto"

    #elif defined(CLAM)

        "xQKq1LwJQQkg1A5cmB9znGozCKLkAaKJHW"

    #elif defined(PAYCON)

        "PShpEEfcy8UrBPWoefsNnq8oz6bX7dNxnP"

    #elif defined(JUMBUCKS)

        "JhbrvAmM7kNpwA6wD5KoAsbtikLWWMNPcM"

    #elif defined(MYRIADCOIN)

        "MDiceoNDTQboRxYKMTstxxRBY493Lg9bV2"

    #elif defined(UNOBTANIUM)

        "udicetdXSo6Zc7vhWgAZfz4XrwagAX34RK"

    #else

        fatal("no address specified")

    #endif
    ;

    warning("no addresses specified, using popular address %s", addr);
    return addr;
}

#if defined(DARKCOIN)

    #include <h9/h9.h>

    void h9(
              uint8_t *h9r,
        const uint8_t *buf,
        uint64_t      size
    ) {
        uint256 hash = Hash9(buf, size + buf);
        memcpy(h9r, &hash, sizeof(hash));
    }

#endif

#if defined(PAYCON)

    #include <h9/h13.h>

    void h13(
        uint8_t       *h9r,
        const uint8_t *buf,
        uint64_t      size
    ) {
        uint256 hash = Hash13(buf, size + buf);
        memcpy(h9r, &hash, sizeof(hash));
    }

#endif

#if defined(CLAM) || defined(JUMBUCKS)

    #include <scrypt/scrypt.h>

    void scrypt(
              uint8_t *scr,
        const uint8_t *buf,
        uint64_t      size
    ) {
        unsigned char scratchpad[SCRYPT_BUFFER_SIZE];
        uint256 hash = scrypt_nosalt(buf, size, scratchpad);
        memcpy(scr, &hash, sizeof(hash));
    }

#endif

void canonicalHexDump(
    const uint8_t *p,
           size_t size,
       const char *indent
) {
    const uint8_t *s =        p;
    const uint8_t *e = size + p;
    while(p<e) {

        printf(
            "%s%06x: ",
            indent,
            (int)(p-s)
        );

        const uint8_t *lp = p;
        const uint8_t *np = 16 + p;
        const uint8_t *le = std::min(e, 16+p);
        while(lp<np) {
            if(lp<le) printf("%02x ", (int)*lp);
            else      printf("   ");
            ++lp;
        }
        printf("  ");

        lp = p;
        while(lp<le) {
            int c = *(lp++);
            printf("%c", isprint(c) ? c : '.');
        }

        printf("\n");
        p = np;
    }
}

void showScriptInfo(
    const uint8_t *outputScript,
    uint64_t      outputScriptSize,
    const uint8_t *indent
) {

    uint8_t addrType[128];
    const char *typeName = "unknown";
    uint8_t pubKeyHash[kSHA256ByteSize];
    auto scriptType = solveOutputScript(
        pubKeyHash,
        outputScript,
        outputScriptSize,
        addrType
    );

    switch(scriptType) {
        case 0: {
            typeName = "pays to hash160(pubKey)";
            break;
        }
        case 1: {
            typeName = "pays to explicit uncompressed pubKey";
            break;
        }
        case 2: {
            typeName = "pays to explicit compressed pubKey";
            break;
        }
        case 3: {
            typeName = "pays to hash160(script)";
            break;
        }
        case 4: {
            typeName = "M of N multi-sig";
            break;
        }
        case -4: {
            typeName = "pays to 0=hash160(X) ... challenge script: anyone who can find X such that 0==RIPEMD160(X) stands to earn a bunch of coins";
            break;
        }
        case -3: {
            typeName = "non functional comment script - coins lost";
            break;
        }
        case -2: {
            typeName = "broken script generated by p2pool - coins lost";
            break;
        }
        case -1: {
            typeName = "couldn't parse script";
            break;
        }
    }
    printf(
        "%sscriptType = '%s'\n",
        indent,
        typeName
    );

    if(0<=scriptType) {
        uint8_t btcAddr[64];
        hash160ToAddr(btcAddr, pubKeyHash, false, addrType[0]);
        printf(
            "%sscriptPaysToAddr = '%s'\n",
            indent,
            btcAddr
        );
        printf(
            "%sscriptPaysToHash160 = '",
            indent
        );
        showHex(pubKeyHash, kRIPEMD160ByteSize, false);
        printf("'\n");
    }
}

static inline void writeEscapedChar(
    int  c,
    FILE *f
) {
         if(unlikely(0==c))  { fputc('\\', f); c = '0'; }
    else if(unlikely('\n'==c)) fputc('\\', f);
    else if(unlikely('\t'==c)) fputc('\\', f);
    else if(unlikely('\\'==c)) fputc('\\', f);
    fputc(c, f);
}

void writeEscapedBinaryBufferRev(
    FILE          *f,
    const uint8_t *p,
    size_t        n
) {
    p += n;
    while(n--) {
        uint8_t c = *(--p);
        writeEscapedChar(c, f);
    }
}

void writeEscapedBinaryBuffer(
    FILE          *f,
    const uint8_t *p,
    size_t        n
) {
    while(n--) {
        uint8_t c = *(p++);
        writeEscapedChar(c, f);
    }
}

