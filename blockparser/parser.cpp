
#include <util.h>
#include <timer.h>
#include <common.h>
#include <errlog.h>
#include <callback.h>

#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <inttypes.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdlib.h>
#include <time.h>
#include <limits>
#include <sys/stat.h>
#include <sys/types.h>
#include <boost/multiprecision/cpp_int.hpp>

#if defined(_WIN32) || defined(_WIN64)
    #ifndef O_BINARY
        #define O_BINARY _O_BINARY
    #endif
#endif

#ifndef O_BINARY
    #define O_BINARY 0
#endif

#if !defined(S_ISDIR)
    #define S_ISDIR(mode) (S_IFDIR==((mode) & S_IFMT))
#endif

typedef GoogMap<
    Hash256,
    Chunk*,
    Hash256Hasher,
    Hash256Equal
>::Map TXOMap;

typedef GoogMap<
    Hash256,
    Block*,
    Hash256Hasher,
    Hash256Equal
>::Map BlockMap;

static bool gNeedUpstream;
static Callback *gCallback;

static const BlockFile *gCurBlockFile;
static std::vector<BlockFile> blockFiles;
static std::string gBlockDirOverride;
static std::vector<char*> gFilteredArgv;

static TXOMap gTXOMap;
static BlockMap gBlockMap;
static uint8_t empty[kSHA256ByteSize] = { 0x42 };

static Block *gMaxBlock;
static Block *gNullBlock;
static int64_t gMaxHeight;
static ChainWork gMaxChainWork;
static uint64_t gChainSize;
static uint256_t gNullHash;
static int64_t gTimeLimit = -1;
static bool gUseTimeLimit = false;
static size_t gRejectedBasicHeaders = 0;
static size_t gRejectedContextHeaders = 0;
static size_t gRejectedVersionHeaders = 0;

static constexpr int64_t kMaxFutureBlockDrift = 2 * 60 * 60;

#if defined(BITCOIN)
    static constexpr int32_t kBip34Height = 227931;
    static constexpr int32_t kBip65Height = 388381;
    static constexpr int32_t kBip66Height = 363725;
    static const char *kConsensusPowLimitHex = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
#elif defined(TESTNET3)
    static constexpr int32_t kBip34Height = 21111;
    static constexpr int32_t kBip65Height = 581885;
    static constexpr int32_t kBip66Height = 330776;
    static const char *kConsensusPowLimitHex = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
#else
    static constexpr int32_t kBip34Height = std::numeric_limits<int32_t>::max();
    static constexpr int32_t kBip65Height = std::numeric_limits<int32_t>::max();
    static constexpr int32_t kBip66Height = std::numeric_limits<int32_t>::max();
    static const char *kConsensusPowLimitHex = 0;
#endif

static double getMem() {

    #if defined(linux)
        char statFileName[256];
        sprintf(
            statFileName,
            "/proc/%d/statm",
            (int)getpid()
        );

        uint64_t mem = 0;
        FILE *f = fopen(statFileName, "r");
            if(1!=fscanf(f, "%" PRIu64, &mem)) {
                warning("coudln't read process size");
            }
        fclose(f);
        return (1e-9f*mem)*getpagesize();
    #elif defined(_WIN64)
        return 0;   // TODO
    #else
        return 0;   // TODO
    #endif
}

#if defined BITCOIN
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".bitcoin";
    static const uint32_t gExpectedMagic = 0xd9b4bef9;
#endif

#if defined TESTNET3
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".bitcoin/testnet3";
    static const uint32_t gExpectedMagic = 0x0709110b;
#endif

#if defined LITECOIN
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".litecoin";
    static const uint32_t gExpectedMagic = 0xdbb6c0fb;
#endif

#if defined DARKCOIN
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".darkcoin";
    static const uint32_t gExpectedMagic = 0xbd6b0cbf;
#endif

#if defined PROTOSHARES
    static const size_t gHeaderSize = 88;
    static auto kCoinDirName = ".protoshares";
    static const uint32_t gExpectedMagic = 0xd9b5bdf9;
#endif

#if defined FEDORACOIN
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".fedoracoin";
    static const uint32_t gExpectedMagic = 0xdead1337;
#endif

#if defined PEERCOIN
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".ppcoin";
    static const uint32_t gExpectedMagic = 0xe5e9e8e6;
#endif

#if defined CLAM
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".clam";
    static const uint32_t gExpectedMagic = 0x15352203;
#endif

#if defined PAYCON
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".PayCon";
    static const uint32_t gExpectedMagic = 0x2d3b3c4b;
#endif

#if defined JUMBUCKS
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".coinmarketscoin";
    static const uint32_t gExpectedMagic = 0xb6f1f4fc;
#endif

#if defined MYRIADCOIN
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".myriadcoin";
    static const uint32_t gExpectedMagic = 0xee7645af;
#endif

#if defined UNOBTANIUM
    static const size_t gHeaderSize = 80;
    static auto kCoinDirName = ".unobtanium";
    static const uint32_t gExpectedMagic = 0x03b5d503;
#endif

#define DO(x) x
    static inline void   startBlock(const uint8_t *p)                      { DO(gCallback->startBlock(p));         }
    static inline void     endBlock(const uint8_t *p)                      { DO(gCallback->endBlock(p));           }
    static inline void     startTXs(const uint8_t *p)                      { DO(gCallback->startTXs(p));           }
    static inline void       endTXs(const uint8_t *p)                      { DO(gCallback->endTXs(p));             }
    static inline void      startTX(const uint8_t *p, const uint8_t *hash) { DO(gCallback->startTX(p, hash));      }
    static inline void        endTX(const uint8_t *p)                      { DO(gCallback->endTX(p));              }
    static inline void  startInputs(const uint8_t *p)                      { DO(gCallback->startInputs(p));        }
    static inline void    endInputs(const uint8_t *p)                      { DO(gCallback->endInputs(p));          }
    static inline void   startInput(const uint8_t *p)                      { DO(gCallback->startInput(p));         }
    static inline void     endInput(const uint8_t *p)                      { DO(gCallback->endInput(p));           }
    static inline void startOutputs(const uint8_t *p)                      { DO(gCallback->startOutputs(p));       }
    static inline void   endOutputs(const uint8_t *p)                      { DO(gCallback->endOutputs(p));         }
    static inline void  startOutput(const uint8_t *p)                      { DO(gCallback->startOutput(p));        }
    static inline void        start(const Block *s, const Block *e)        { DO(gCallback->start(s, e));           }
#undef DO

static inline void   startBlockFile(const uint8_t *p)                      { gCallback->startBlockFile(p);         }
static inline void     endBlockFile(const uint8_t *p)                      { gCallback->endBlockFile(p);           }
static inline void         startBlock(const Block *b)                      { gCallback->startBlock(b, gChainSize); }
static inline void           endBlock(const Block *b)                      { gCallback->endBlock(b);               }
static inline bool                             done()                      { return gCallback->done();             }

static inline void endOutput(
    const uint8_t *p,
    uint64_t      value,
    const uint8_t *txHash,
    uint64_t      outputIndex,
    const uint8_t *outputScript,
    uint64_t      outputScriptSize
) {
    gCallback->endOutput(
        p,
        value,
        txHash,
        outputIndex,
        outputScript,
        outputScriptSize
    );
}

using boost::multiprecision::cpp_int;

static cpp_int powLimitFromHex(const char *hex) {
    cpp_int value = 0;
    if(0 == hex) {
        return value;
    }
    while(*hex) {
        char c = *hex++;
        int nibble = -1;
        if('0'<=c && c<='9') {
            nibble = c - '0';
        } else if('a'<=c && c<='f') {
            nibble = 10 + (c - 'a');
        } else if('A'<=c && c<='F') {
            nibble = 10 + (c - 'A');
        } else {
            continue;
        }
        value <<= 4;
        value += nibble;
    }
    return value;
}

static const cpp_int &GetConsensusPowLimit() {
    static const cpp_int powLimit = powLimitFromHex(kConsensusPowLimitHex);
    return powLimit;
}

static cpp_int hashToCppInt(const uint8_t *hash) {
    cpp_int value = 0;
    for(int i = kSHA256ByteSize - 1; i >= 0; --i) {
        value <<= 8;
        value += hash[i];
    }
    return value;
}

static bool decodeCompactBits(uint32_t bits, cpp_int &target) {
    target = 0;
    if(bits & 0x00800000U) {
        return false;
    }

    uint32_t mantissa = bits & 0x007fffffU;
    if(mantissa == 0) {
        return false;
    }

    int exponent = bits >> 24;
    if(exponent <= 0) {
        return false;
    }

    target = mantissa;
    if(exponent <= 3) {
        target >>= 8 * (3 - exponent);
    } else {
        target <<= 8 * (exponent - 3);
    }
    return true;
}

static bool checkProofOfWork(const Block *block) {
    cpp_int target;
    if(!decodeCompactBits(block->bits, target)) {
        uint8_t hashHex[2*kSHA256ByteSize + 1];
        toHex(hashHex, block->hash);
        warning(
            "block %s has invalid compact target encoding (bits=%08" PRIx32 ")",
            hashHex,
            block->bits
        );
        return false;
    }

    if(target <= 0) {
        uint8_t hashHex[2*kSHA256ByteSize + 1];
        toHex(hashHex, block->hash);
        warning("block %s encodes non-positive work target", hashHex);
        return false;
    }

    if(0 != kConsensusPowLimitHex) {
        const cpp_int &powLimit = GetConsensusPowLimit();
        if(powLimit != 0 && target > powLimit) {
            uint8_t hashHex[2*kSHA256ByteSize + 1];
            toHex(hashHex, block->hash);
            warning(
                "block %s target exceeds consensus limit", hashHex
            );
            return false;
        }
    }

    cpp_int hashValue = hashToCppInt(block->hash);
    if(hashValue > target) {
        uint8_t hashHex[2*kSHA256ByteSize + 1];
        toHex(hashHex, block->hash);
        warning(
            "block %s fails proof-of-work check", hashHex
        );
        return false;
    }

    return true;
}

static bool checkBlockTime(const Block *block) {
    time_t now = time(0);
    if(now < 0) {
        now = 0;
    }
    int64_t limit = static_cast<int64_t>(now) + kMaxFutureBlockDrift;
    if(static_cast<int64_t>(block->time) > limit) {
        uint8_t hashHex[2*kSHA256ByteSize + 1];
        toHex(hashHex, block->hash);
        warning(
            "block %s timestamp %" PRIu32 " exceeds allowable future drift",
            hashHex,
            block->time
        );
        return false;
    }
    return true;
}

static bool validateBlockHeaderBasics(Block *block) {
    if(!checkProofOfWork(block)) {
        ++gRejectedBasicHeaders;
        return false;
    }
    if(!checkBlockTime(block)) {
        ++gRejectedBasicHeaders;
        return false;
    }
    block->headerValidated = true;
    return true;
}

static uint32_t computeMedianTimePast(const Block *parent) {
    std::vector<uint32_t> samples;
    samples.reserve(11);
    const Block *cursor = parent;
    while(cursor && cursor != gNullBlock && samples.size() < 11) {
        samples.push_back(cursor->time);
        cursor = cursor->prev;
    }
    if(samples.empty()) {
        return 0;
    }
    std::vector<uint32_t> ordered = samples;
    size_t mid = ordered.size() / 2;
    std::nth_element(ordered.begin(), ordered.begin() + mid, ordered.end());
    return ordered[mid];
}

static bool validateContextualBlockHeader(
    const Block *block,
    const Block *parent,
    bool        &missingContext,
    bool         logFailures
) {
    missingContext = false;
    if(0==parent) {
        missingContext = true;
        return false;
    }
    if(parent->invalid || !parent->headerValidated) {
        if(logFailures) {
            uint8_t childHex[2*kSHA256ByteSize + 1];
            toHex(childHex, block->hash);
            uint8_t parentHex[2*kSHA256ByteSize + 1];
            toHex(parentHex, parent->hash);
            warning(
                "block %s references invalid or unchecked parent %s",
                childHex,
                parentHex
            );
        }
        ++gRejectedContextHeaders;
        return false;
    }

    uint32_t median = computeMedianTimePast(parent);
    if(median != 0 && block->time <= median) {
        if(logFailures) {
            uint8_t hashHex[2*kSHA256ByteSize + 1];
            toHex(hashHex, block->hash);
            warning(
                "block %s timestamp %" PRIu32 " is not greater than median past %" PRIu32,
                hashHex,
                block->time,
                median
            );
        }
        ++gRejectedContextHeaders;
        return false;
    }

    return true;
}

static bool checkVersionForHeight(const Block *block, int64_t height) {
    if(height >= kBip34Height && block->version < 2) {
        uint8_t hashHex[2*kSHA256ByteSize + 1];
        toHex(hashHex, block->hash);
        warning(
            "block %s at height %" PRId64 " has version %" PRId32 " below BIP34 minimum",
            hashHex,
            height,
            block->version
        );
        ++gRejectedVersionHeaders;
        return false;
    }
    if(height >= kBip66Height && block->version < 3) {
        uint8_t hashHex[2*kSHA256ByteSize + 1];
        toHex(hashHex, block->hash);
        warning(
            "block %s at height %" PRId64 " has version %" PRId32 " below BIP66 minimum",
            hashHex,
            height,
            block->version
        );
        ++gRejectedVersionHeaders;
        return false;
    }
    if(height >= kBip65Height && block->version < 4) {
        uint8_t hashHex[2*kSHA256ByteSize + 1];
        toHex(hashHex, block->hash);
        warning(
            "block %s at height %" PRId64 " has version %" PRId32 " below BIP65 minimum",
            hashHex,
            height,
            block->version
        );
        ++gRejectedVersionHeaders;
        return false;
    }
    return true;
}

static ChainWork makeZeroChainWork() {
    ChainWork work;
    for(int i = 0; i < 4; ++i) {
        work.words[i] = 0;
    }
    return work;
}

static ChainWork chainWorkFromCppInt(const cpp_int &value) {
    ChainWork work = makeZeroChainWork();
    cpp_int tmp = value;
    for(int i = 0; i < 4; ++i) {
        work.words[i] = static_cast<uint64_t>(tmp & 0xffffffffffffffffULL);
        tmp >>= 64;
    }
    return work;
}

static inline void chainWorkAdd(ChainWork &accumulator, const ChainWork &value) {
    uint64_t carry = 0;
    for(int i = 0; i < 4; ++i) {
        uint64_t current = accumulator.words[i];
        uint64_t addend = value.words[i];
        uint64_t sum = current + addend;
        uint64_t result = sum + carry;
        uint64_t newCarry = 0;
        if(sum < current) {
            newCarry = 1;
        }
        if(result < sum) {
            ++newCarry;
        }
        accumulator.words[i] = result;
        carry = newCarry;
    }
}

static inline int chainWorkCompare(const ChainWork &a, const ChainWork &b) {
    for(int i = 3; i >= 0; --i) {
        if(a.words[i] < b.words[i]) {
            return -1;
        }
        if(a.words[i] > b.words[i]) {
            return 1;
        }
    }
    return 0;
}

static void chainWorkToHex(const ChainWork &work, char *out, size_t outSize) {
    if(outSize < 65) {
        if(outSize > 0) {
            out[0] = 0;
        }
        return;
    }
    char *cursor = out;
    for(int i = 3; i >= 0; --i) {
        size_t consumed = static_cast<size_t>(cursor - out);
        size_t remaining = outSize - consumed;
        int written = snprintf(cursor, remaining, "%016" PRIx64, work.words[i]);
        if(written < 0) {
            out[0] = 0;
            return;
        }
        cursor += written;
    }
    out[64] = 0;
}

static ChainWork computeBlockProof(uint32_t bits) {
    if(bits & 0x00800000U) {
        return makeZeroChainWork();
    }

    uint32_t mantissa = bits & 0x007fffffU;
    if(mantissa == 0) {
        return makeZeroChainWork();
    }

    int exponent = bits >> 24;
    cpp_int target = mantissa;
    if(exponent <= 3) {
        target >>= 8 * (3 - exponent);
    } else {
        target <<= 8 * (exponent - 3);
    }

    if(target <= 0) {
        return makeZeroChainWork();
    }

    const cpp_int maxValue = (cpp_int(1) << 256) - 1;
    if(target > maxValue) {
        return makeZeroChainWork();
    }

    cpp_int denominator = target + 1;
    cpp_int numerator = maxValue - target;
    cpp_int proof = (numerator / denominator) + 1;
    if(proof < 0) {
        return makeZeroChainWork();
    }
    return chainWorkFromCppInt(proof);
}

static inline void edge(
    uint64_t      value,
    const uint8_t *upTXHash,
    uint64_t      outputIndex,
    const uint8_t *outputScript,
    uint64_t      outputScriptSize,
    const uint8_t *downTXHash,
    uint64_t      inputIndex,
    const uint8_t *inputScript,
    uint64_t      inputScriptSize
) {
    gCallback->edge(
        value,
        upTXHash,
        outputIndex,
        outputScript,
        outputScriptSize,
        downTXHash,
        inputIndex,
        inputScript,
        inputScriptSize
    );
}

template<
    bool skip,
    bool fullContext
>
static void parseOutput(
    const uint8_t *&p,
    const uint8_t *txHash,
    uint64_t      outputIndex,
    const uint8_t *downTXHash,
    uint64_t      downInputIndex,
    const uint8_t *downInputScript,
    uint64_t      downInputScriptSize,
    bool          found = false
) {
    if(!skip && !fullContext) {
        startOutput(p);
    }

        LOAD(uint64_t, value, p);
        LOAD_VARINT(outputScriptSize, p);

        auto outputScript = p;
        p += outputScriptSize;

        if(!skip && fullContext && found) {
            edge(
                value,
                txHash,
                outputIndex,
                outputScript,
                outputScriptSize,
                downTXHash,
                downInputIndex,
                downInputScript,
                downInputScriptSize
            );
        }

    if(!skip && !fullContext) {
        endOutput(
            p,
            value,
            txHash,
            outputIndex,
            outputScript,
            outputScriptSize
        );
    }
}

template<
    bool skip,
    bool fullContext
>
static void parseOutputs(
    const uint8_t *&p,
    const uint8_t *txHash,
    uint64_t      stopAtIndex = -1,
    const uint8_t *downTXHash = 0,
    uint64_t      downInputIndex = 0,
    const uint8_t *downInputScript = 0,
    uint64_t      downInputScriptSize = 0
) {
    if(!skip && !fullContext) {
        startOutputs(p);
    }

        LOAD_VARINT(nbOutputs, p);
        for(uint64_t outputIndex=0; outputIndex<nbOutputs; ++outputIndex) {
            auto found = (fullContext && !skip && (stopAtIndex==outputIndex));
            parseOutput<skip, fullContext>(
                p,
                txHash,
                outputIndex,
                downTXHash,
                downInputIndex,
                downInputScript,
                downInputScriptSize,
                found
            );
            if(found) {
                break;
            }
        }

    if(!skip && !fullContext) {
        endOutputs(p);
    }
}

template<
    bool skip
>
static void parseInput(
    const Block   *block,
    const uint8_t *&p,
    const uint8_t *txHash,
    uint64_t      inputIndex
) {
    if(!skip) {
        startInput(p);
    }

        auto upTXHash = p;
        const Chunk *upTX = 0;
        if(gNeedUpstream && !skip) {
            auto isGenTX = (0==memcmp(gNullHash.v, upTXHash, sizeof(gNullHash)));
            if(likely(false==isGenTX)) {
                auto i = gTXOMap.find(upTXHash);
                if(unlikely(gTXOMap.end()==i)) {
                    errFatal("failed to locate upstream transaction");
                }
                upTX = i->second;
            }
        }

        SKIP(uint256_t, dummyUpTXhash, p);
        LOAD(uint32_t, upOutputIndex, p);
        LOAD_VARINT(inputScriptSize, p);

        if(!skip && 0!=upTX) {
            auto inputScript = p;
            auto upTXOutputs = upTX->getData();
                parseOutputs<false, true>(
                    upTXOutputs,
                    upTXHash,
                    upOutputIndex,
                    txHash,
                    inputIndex,
                    inputScript,
                    inputScriptSize
                );
            upTX->releaseData();
        }

        p += inputScriptSize;
        SKIP(uint32_t, sequence, p);

    if(!skip) {
        endInput(p);
    }
}

template<
    bool skip
>
static void parseInputs(
    const Block   *block,
    const uint8_t *&p,
    const uint8_t *txHash
) {
    if(!skip) {
        startInputs(p);
    }

    LOAD_VARINT(nbInputs, p);
    for(uint64_t inputIndex=0; inputIndex<nbInputs; ++inputIndex) {
        parseInput<skip>(
            block,
            p,
            txHash,
            inputIndex
        );
    }

    if(!skip) {
        endInputs(p);
    }
}

template<
    bool skip
>
static void parseTX(
    const Block   *block,
    const uint8_t *&p
) {
    auto txStart = p;
    uint8_t *txHash = 0;

    if(gNeedUpstream && !skip) {
        auto txEnd = p;
        txHash = allocHash256();
        parseTX<true>(block, txEnd);
        sha256Twice(txHash, txStart, txEnd - txStart);
    }

    if(!skip) {
        startTX(p, txHash);
    }

        #if defined(CLAM)
            LOAD(uint32_t, nVersion, p);
        #else
            SKIP(uint32_t, nVersion, p);
        #endif

        #if defined(PEERCOIN) || defined(CLAM) || defined(JUMBUCKS) || defined(PAYCON)
            SKIP(uint32_t, nTime, p);
        #endif

        parseInputs<skip>(block, p, txHash);

        Chunk *txo = 0;
        size_t txoOffset = -1;
        const uint8_t *outputsStart = p;
        if(gNeedUpstream && !skip) {
            txo = Chunk::alloc();
            gTXOMap[txHash] = txo;
            txoOffset = block->chunk->getOffset() + (p - block->chunk->getData());
        }

        parseOutputs<skip, false>(p, txHash);

        if(txo) {
            size_t txoSize = p - outputsStart;
            txo->init(
                block->chunk->getBlockFile(),
                txoSize,
                txoOffset
            );
        }

        SKIP(uint32_t, lockTime, p);

        #if defined(CLAM)
            if(1<nVersion) {
                LOAD_VARINT(strCLAMSpeechLen, p);
                p += strCLAMSpeechLen;
            }
        #endif

    if(!skip) {
        endTX(p);
    }
}

static bool parseBlock(
    const Block *block
) {
    startBlock(block);
        auto p = block->chunk->getData();

            auto header = p;
            SKIP(uint32_t, version, p);
            SKIP(uint256_t, prevBlkHash, p);
            SKIP(uint256_t, blkMerkleRoot, p);
            SKIP(uint32_t, blkTime, p);
            SKIP(uint32_t, blkBits, p);
            SKIP(uint32_t, blkNonce, p);

            #if defined PROTOSHARES
                SKIP(uint32_t, nBirthdayA, p);
                SKIP(uint32_t, nBirthdayB, p);
            #endif

            startTXs(p);
                LOAD_VARINT(nbTX, p);
                for(uint64_t txIndex=0; likely(txIndex<nbTX); ++txIndex) {
                    parseTX<false>(block, p);
                    if(done()) {
                        return true;
                    }
                }
            endTXs(p);

            #if defined(PEERCOIN) || defined(CLAM) || defined(JUMBUCKS) || defined(PAYCON)
                LOAD_VARINT(vchBlockSigSize, p);
                p += vchBlockSigSize;
            #endif

        block->chunk->releaseData();
    endBlock(block);
    return done();
}

static void parseLongestChain() {

    info(
        "pass 4 -- full blockchain analysis (with%s index)...",
        gNeedUpstream ? "" : "out"
    );

    auto startTime = Timer::usecs();
    gCallback->startLC();

        uint64_t bytesSoFar =  0;
        auto blk = gNullBlock->next;
        start(blk, gMaxBlock);

        while(likely(0!=blk)) {

            if(0==(blk->height % 10)) {
   
                auto now = Timer::usecs();
                static auto last = -1.0;
                auto elapsedSinceLastTime = now - last;
                auto elapsedSinceStart = now - startTime;
                auto progress =  bytesSoFar/(double)gChainSize;
                auto bytesPerSec = bytesSoFar / (elapsedSinceStart*1e-6);
                auto bytesLeft = gChainSize - bytesSoFar;
                auto secsLeft = bytesLeft / bytesPerSec;
                if((1.0 * 1000 * 1000)<elapsedSinceLastTime) {
                    char currentWork[65];
                    char tipWork[65];
                    chainWorkToHex(blk->chainWork, currentWork, sizeof(currentWork));
                    chainWorkToHex(gMaxChainWork, tipWork, sizeof(tipWork));
                    fprintf(
                        stderr,
                        "block %6d/%6d (work 0x%s/0x%s), %.2f%% done, ETA = %.2fsecs, mem = %.3f Gig           \r",
                        (int)blk->height,
                        (int)gMaxHeight,
                        currentWork,
                        tipWork,
                        progress*100.0,
                        secsLeft,
                        getMem()
                    );
                    fflush(stderr);
                    last = now;
                }
            }

            if(parseBlock(blk)) {
                break;
            }

            bytesSoFar += blk->chunk->getSize();
            blk = blk->next;
        }

    fprintf(stderr, "                                                          \r");
    gCallback->wrapup();

    info("pass 4 -- done.");
}

static void wireLongestChain() {

    info("pass 3 -- wire longest chain ...");

    auto block = gMaxBlock;
    while(1) {
        auto prev = block->prev;
        if(unlikely(0==prev)) {
            break;
        }
        prev->next = block;
        block = prev;
    }

    char workHex[65];
    chainWorkToHex(gMaxChainWork, workHex, sizeof(workHex));
    info(
        "pass 3 -- done, bestHeight=%d, chainWork=0x%s",
        (int)gMaxHeight,
        workHex
    );
}

static void initCallback(
    int   argc,
    char *argv[]
) {
    const char *methodName = 0;
    if(0<argc) {
        methodName = argv[1];
    }
    if(0==methodName) {
        methodName = "";
    }
    if(0==methodName[0]) {
        methodName = "help";
    }
    gCallback = Callback::find(methodName);

    info("starting command \"%s\"", gCallback->name());
    if(argv[1]) {
        auto i = 0;
        while('-'==argv[1][i]) {
            argv[1][i++] = 'x';
        }
    }

    auto ir = gCallback->init(argc, (const char **)argv);
    if(ir<0) {
        errFatal("callback init failed");
    }
    gNeedUpstream = gCallback->needUpstream();

    if(done()) {
        fprintf(stderr, "\n");
        exit(0);
    }
}

static void findBlockParent(
    Block *b
) {
    if(unlikely(0==b || b->invalid || !b->headerValidated)) {
        return;
    }

    b->prev = 0;

    auto where = lseek64(
        b->chunk->getBlockFile()->fd,
        b->chunk->getOffset(),
        SEEK_SET
    );
    if(where!=(signed)b->chunk->getOffset()) {
        sysErrFatal(
            "failed to seek into block chain file %s",
            b->chunk->getBlockFile()->name.c_str()
        );
    }

    uint8_t buf[gHeaderSize];
    auto nbRead = read(
        b->chunk->getBlockFile()->fd,
        buf,
        gHeaderSize
    );
    if(nbRead<(signed)gHeaderSize) {
        sysErrFatal(
            "failed to read from block chain file %s",
            b->chunk->getBlockFile()->name.c_str()
        );
    }

    auto i = gBlockMap.find(4 + buf);
    if(unlikely(gBlockMap.end()==i)) {

        uint8_t bHash[2*kSHA256ByteSize + 1];
        toHex(bHash, b->hash);

        uint8_t pHash[2*kSHA256ByteSize + 1];
        toHex(pHash, 4 + buf);

        warning(
            "in block %s (height=%" PRId64 ", time=%" PRIu32 ", file=%s, offset=%" PRIu64 ") failed to locate parent block %s",
            bHash,
            static_cast<int64_t>(b->height),
            static_cast<uint32_t>(b->time),
            b->chunk->getBlockFile()->name.c_str(),
            static_cast<uint64_t>(b->chunk->getOffset()),
            pHash
        );
        return;
    }

    Block *candidate = i->second;
    bool missingContext = false;
    if(!validateContextualBlockHeader(b, candidate, missingContext, true)) {
        if(missingContext) {
            return;
        }
        b->invalid = true;
        return;
    }

    b->prev = candidate;
    b->contextValidated = true;
}

static void computeBlockHeight(
    Block  *block,
    size_t &lateLinks
) {

    if(unlikely(gNullBlock==block)) {
        return;
    }

    if(block->invalid || !block->headerValidated) {
        return;
    }

    if(block->height>=0) {
        return;
    }

    auto b = block;
    while(b->height<0 && gNullBlock!=b) {

        if(b->invalid || !b->headerValidated) {
            return;
        }

        if(unlikely(0==b->prev)) {

            findBlockParent(b);
            ++lateLinks;

            if(0==b->prev) {
                warning("failed to locate parent block");
                return;
            }
        }

        if(unlikely(b->prev->invalid || !b->prev->headerValidated)) {

            uint8_t childHex[2*kSHA256ByteSize + 1];
            toHex(childHex, b->hash);

            uint8_t parentHex[2*kSHA256ByteSize + 1];
            toHex(parentHex, b->prev->hash);

            warning(
                "block %s references invalid parent %s",
                childHex,
                parentHex
            );
            b->invalid = true;
            return;
        }

        if(!b->contextValidated) {
            bool missingContext = false;
            if(!validateContextualBlockHeader(b, b->prev, missingContext, true)) {
                if(!missingContext) {
                    b->invalid = true;
                }
                return;
            }
            b->contextValidated = true;
        }

        b->prev->next = b;
        b = b->prev;
    }

    auto height = b->height;
    while(1) {

        auto next = b->next;
        b->next = 0;

        if(unlikely(0==next)) {
            break;
        }

        b = next;

        if(b->invalid || !b->headerValidated) {
            continue;
        }

        if(unlikely(0==b->prev)) {
            continue;
        }

        if(unlikely(b->prev->invalid || b->prev->height<0)) {
            if(b->prev->invalid) {
                b->invalid = true;
                continue;
            }
            computeBlockHeight(b->prev, lateLinks);
            if(b->prev->height<0) {
                continue;
            }
        }

        height = b->prev->height;
        b->height = height + 1;

        if(!b->contextValidated) {
            bool missingContext = false;
            if(!validateContextualBlockHeader(b, b->prev, missingContext, true)) {
                if(!missingContext) {
                    b->invalid = true;
                }
                b->height = -1;
                continue;
            }
            b->contextValidated = true;
        }

        if(!checkVersionForHeight(b, b->height)) {
            b->invalid = true;
            b->height = -1;
            continue;
        }
        b->versionValidated = true;

        ChainWork proof = computeBlockProof(b->bits);
        if(likely(0!=b->prev)) {
            b->chainWork = b->prev->chainWork;
            chainWorkAdd(b->chainWork, proof);
        } else {
            b->chainWork = proof;
        }

        int cmp = chainWorkCompare(gMaxChainWork, b->chainWork);
        if(likely(cmp < 0 || (0==cmp && gMaxHeight < b->height))) {
            gMaxChainWork = b->chainWork;
            gMaxHeight = b->height;
            gMaxBlock = b;
        }

        if(block==b) {
            break;
        }
    }
}

static void computeBlockHeights() {

    size_t lateLinks = 0;
    size_t initialContextRejects = gRejectedContextHeaders;
    size_t initialVersionRejects = gRejectedVersionHeaders;
    info("pass 2 -- link all blocks ...");
    for(const auto &pair:gBlockMap) {
        computeBlockHeight(pair.second, lateLinks);
    }
    size_t pass2ContextRejects = gRejectedContextHeaders - initialContextRejects;
    size_t pass2VersionRejects = gRejectedVersionHeaders - initialVersionRejects;
    info(
        "pass 2 -- done, did %d late links, %zu contextual rejects, %zu version rejects",
        (int)lateLinks,
        pass2ContextRejects,
        pass2VersionRejects
    );
}

static void getBlockHeader(
    size_t        &size,
    Block        *&prev,
    uint8_t      *&hash,
    size_t        &earlyMissCnt,
    const uint8_t *p
) {

    LOAD(uint32_t, magic, p);
    if(unlikely(gExpectedMagic!=magic)) {
        hash = 0;
        return;
    }

    LOAD(uint32_t, sz, p);
    size = sz;
    prev = 0;

    hash = allocHash256();

    #if defined(DARKCOIN)
        h9(hash, p, gHeaderSize);
    #elif defined(PAYCON)
        h13(hash, p, gHeaderSize);
    #elif defined(CLAM)
        auto pBis = p;
        LOAD(uint32_t, nVersion, pBis);
        if(6<nVersion) {
            sha256Twice(hash, p, gHeaderSize);
        } else {
            scrypt(hash, p, gHeaderSize);
        }
    #elif defined(JUMBUCKS)
        scrypt(hash, p, gHeaderSize);
    #else
        sha256Twice(hash, p, gHeaderSize);
    #endif

    auto i = gBlockMap.find(p + 4);
    if(likely(gBlockMap.end()!=i)) {
        prev = i->second;
    } else {
        ++earlyMissCnt;
    }
}

static void buildBlockHeaders() {

    info("pass 1 -- walk all blocks and build headers ...");

    if(gUseTimeLimit) {
        char isoBuf[32];
        time_t limit = (time_t)gTimeLimit;
        struct tm gmTime;
        gmtime_r(&limit, &gmTime);
        snprintf(
            isoBuf,
            sizeof(isoBuf),
            "%04d-%02d-%02d %02d:%02d:%02d",
            gmTime.tm_year + 1900,
            gmTime.tm_mon + 1,
            gmTime.tm_mday,
            gmTime.tm_hour,
            gmTime.tm_min,
            gmTime.tm_sec
        );
        info("limiting block scan to timestamps <= %s (UTC)", isoBuf);
    }

    size_t nbBlocks = 0;
    uint64_t baseOffset = 0;
    size_t earlyMissCnt = 0;
    uint8_t buf[8+gHeaderSize];
    const auto sz = sizeof(buf);
    const auto startTime = Timer::usecs();
    const auto oneMeg = 1024 * 1024;
    bool limitReached = false;
    uint64_t effectiveSize = 0;

    for(const auto &blockFile : blockFiles) {

        if(limitReached) {
            break;
        }

        startBlockFile(0);

        uint64_t fileBytesRead = 0;
        bool fileLimitReached = false;

        while(1) {

            auto nbRead = read(blockFile.fd, buf, sz);
            if(nbRead<(signed)sz) {
                break;
            }

            const uint8_t *timePtr = buf + 8 + 4 + 32 + 32;
            LOAD(uint32_t, rawTime, timePtr);
            uint32_t blockTime = rawTime;
            const uint8_t *bitsPtr = timePtr + 4;
            uint32_t blockBits = 0;
            LOAD(uint32_t, blockBits, bitsPtr);

            if(gUseTimeLimit && ((int64_t)blockTime > gTimeLimit)) {
                auto cur = lseek(blockFile.fd, 0, SEEK_CUR);
                if(cur<0) {
                    cur = 0;
                }
                fileBytesRead = (uint64_t)cur;
                if(fileBytesRead >= sz) {
                    fileBytesRead -= sz;
                } else {
                    fileBytesRead = 0;
                }
                limitReached = true;
                fileLimitReached = true;
                break;
            }

            startBlock((uint8_t*)0);

            const uint8_t *versionPtr = buf + 8;
            LOAD(int32_t, blockVersion, versionPtr);

            uint8_t *hash = 0;
            Block *prevBlock = 0;
            size_t blockSize = 0;

            getBlockHeader(
                blockSize,
                prevBlock,
                hash,
                earlyMissCnt,
                buf
            );
            if(unlikely(0==hash)) {
                endBlock((uint8_t*)0);
                break;
            }

            auto where = lseek(blockFile.fd, (blockSize + 8) - sz, SEEK_CUR);
            if(where<0) {
                endBlock((uint8_t*)0);
                break;
            }
            auto blockOffset = where - blockSize;
            fileBytesRead = (uint64_t)where;

            auto block = Block::alloc();
            block->init(hash, &blockFile, blockSize, 0, blockOffset, blockTime, blockBits, blockVersion);

            if(!validateBlockHeaderBasics(block)) {
                endBlock((uint8_t*)0);
                continue;
            }

            Block *candidatePrev = prevBlock;
            if(candidatePrev) {
                bool missingContext = false;
                if(validateContextualBlockHeader(block, candidatePrev, missingContext, true)) {
                    block->prev = candidatePrev;
                    block->contextValidated = true;
                } else if(missingContext) {
                    block->prev = 0;
                } else {
                    block->invalid = true;
                    endBlock((uint8_t*)0);
                    continue;
                }
            }

            gBlockMap[hash] = block;
            endBlock((uint8_t*)0);
            ++nbBlocks;

            effectiveSize += blockSize;
        }

        if(fileLimitReached) {
            baseOffset += fileBytesRead;
        } else {
            baseOffset += blockFile.size;
        }

        auto now = Timer::usecs();
        auto elapsed = now - startTime;
        auto elapsedSec = elapsed*1e-6;
        double bytesPerSec = (elapsedSec>0.0) ? baseOffset/elapsedSec : 0.0;
        uint64_t targetSize = limitReached ? baseOffset : gChainSize;
        if(targetSize < baseOffset) {
            targetSize = baseOffset;
        }
        double bytesLeft = (targetSize > baseOffset) ? (targetSize - baseOffset) : 0.0;
        double secsLeft = (bytesPerSec>0.0) ? (bytesLeft / bytesPerSec) : 0.0;
        double progressDen = (targetSize>0) ? (double)targetSize : 1.0;

        fprintf(
            stderr,
            " %.2f%% (%.2f/%.2f Gigs) -- %6d blocks -- %.2f Megs/sec -- ETA %.0f secs -- ELAPSED %.0f secs            \r",
            (100.0*baseOffset)/progressDen,
            baseOffset/(1000.0*oneMeg),
            targetSize/(1000.0*oneMeg),
            (int)nbBlocks,
            bytesPerSec*1e-6,
            secsLeft,
            elapsedSec
        );
        fflush(stderr);

        endBlockFile(0);

        if(limitReached) {
            break;
        }
    }

    if(0==nbBlocks) {
        warning("found no blocks - giving up                                                       ");
        exit(1);
    }

    gChainSize = effectiveSize;

    char msg[256];
    msg[0] = 0;
    size_t msgLen = 0;
    if(0<earlyMissCnt) {
        int written = snprintf(
            msg + msgLen,
            sizeof(msg) - msgLen,
            ", %d early link misses",
            (int)earlyMissCnt
        );
        if(written > 0) {
            msgLen += (size_t)written;
        }
    }
    if(gRejectedBasicHeaders>0) {
        int written = snprintf(
            msg + msgLen,
            sizeof(msg) - msgLen,
            ", filtered %zu invalid headers",
            gRejectedBasicHeaders
        );
        if(written > 0) {
            msgLen += (size_t)written;
        }
    }

    auto elapsed = 1e-6*(Timer::usecs() - startTime);
    info(
        "pass 1 -- took %.0f secs, %6d blocks, %.2f Gigs, %.2f Megs/secs %s, mem=%.3f Gigs",
        elapsed,
        (int)nbBlocks,
        (gChainSize * 1e-9),
        (gChainSize * 1e-6) / elapsed,
        msg,
        getMem()
    );
}

static void buildNullBlock() {
    gBlockMap[gNullHash.v] = gNullBlock = Block::alloc();
    gNullBlock->init(gNullHash.v, 0, 0, 0, 0, 0, 0, 0);
    gNullBlock->headerValidated = true;
    gNullBlock->contextValidated = true;
    gNullBlock->versionValidated = true;
    gNullBlock->invalid = false;
    gNullBlock->height = -1;
    gMaxBlock = gNullBlock;
    gMaxHeight = gNullBlock->height;
    gMaxChainWork = gNullBlock->chainWork;
}

static void initHashtables() {

    info("initializing hash tables");

    gTXOMap.setEmptyKey(empty);
    gBlockMap.setEmptyKey(empty);

    auto kAvgBytesPerTX = 542.0;
    auto nbTxEstimate = (size_t)(1.1 * (gChainSize / kAvgBytesPerTX));
    if(gNeedUpstream) {
        gTXOMap.resize(nbTxEstimate);
    }

    auto kAvgBytesPerBlock = 140000;
    auto nbBlockEstimate = (size_t)(1.1 * (gChainSize / kAvgBytesPerBlock));
    gBlockMap.resize(nbBlockEstimate);

    info("estimated number of blocks = %.2fK", 1e-3*nbBlockEstimate);
    info("estimated number of transactions = %.2fM", 1e-6*nbTxEstimate);
    info("done initializing hash tables - mem = %.3f Gigs", getMem());
}

#if defined(__CYGWIN__)
    #include <sys/cygwin.h>
    #include <cygwin/version.h>
    static char *canonicalize_file_name(
        const char *fileName
    ) {
        auto r = (char*)cygwin_create_path(CCP_WIN_A_TO_POSIX, fileName);
        if(0==r) {
            errFatal("can't canonicalize path %s", fileName);
        }
        return r;
    }
#endif

#if defined(_WIN64)
    static char *canonicalize_file_name(
        const char *fileName
    ) {
        return strdup(fileName);
    }
#endif


static std::string getNormalizedDirName(
    const std::string &dirName
) {

    auto t = canonicalize_file_name(dirName.c_str());
    if(0==t) {
        errFatal(
            "problem accessing directory %s",
            dirName.c_str()
        );
    }

    auto r = std::string(t);
    free(t);

    auto sz = r.size();
    if(0<sz) {
        if('/'==r[sz-1]) {
            r = std::string(r, 0, sz-2);
        }
    }

    return r;
}

static void parseGlobalArgs(
    int   &argc,
    char **&argv
) {

    gFilteredArgv.clear();
    gFilteredArgv.reserve(argc + 1);

    if(0<argc) {
        gFilteredArgv.push_back(argv[0]);
    }

    for(int i=1; i<argc; ++i) {

        auto current = std::string(argv[i]);

        if("--"==current) {
            for(int j=i; j<argc; ++j) {
                gFilteredArgv.push_back(argv[j]);
            }
            break;
        }

        if("-B"==current || "--blocks-dir"==current) {

            if(i+1>=argc) {
                errFatal("option %s requires an argument", current.c_str());
            }

            gBlockDirOverride = argv[++i];
            continue;
        }

        if(0==current.compare(0, 13, "--blocks-dir=")) {
            gBlockDirOverride = current.substr(13);
            continue;
        }

        if("--stop-at-time"==current) {

            if(i+1>=argc) {
                errFatal("option %s requires an argument", current.c_str());
            }

            const char *value = argv[++i];
            int64_t parsed = 0;
            if(!parseTimeString(value, parsed)) {
                errFatal("invalid --stop-at-time value, expected YYYY-MM-DD HH:MM:SS");
            }
            if(parsed<0 || parsed>static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                errFatal("--stop-at-time is outside supported range (1970-01-01 00:00:00 .. 2106-02-07 06:28:15)");
            }
            gTimeLimit = parsed;
            gUseTimeLimit = true;
            continue;
        }

        if(0==current.compare(0, 15, "--stop-at-time=")) {
            auto value = current.substr(15);
            int64_t parsed = 0;
            if(!parseTimeString(value.c_str(), parsed)) {
                errFatal("invalid --stop-at-time value, expected YYYY-MM-DD HH:MM:SS");
            }
            if(parsed<0 || parsed>static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                errFatal("--stop-at-time is outside supported range (1970-01-01 00:00:00 .. 2106-02-07 06:28:15)");
            }
            gTimeLimit = parsed;
            gUseTimeLimit = true;
            continue;
        }

        gFilteredArgv.push_back(argv[i]);
    }

    gFilteredArgv.push_back(0);
    argc = (int)gFilteredArgv.size() - 1;
    argv = gFilteredArgv.data();
}

static std::string getBlockchainDir() {
    if(!gBlockDirOverride.empty()) {
        return getNormalizedDirName(gBlockDirOverride);
    }
    auto dir = getenv("BLOCKCHAIN_DIR");
    if(0==dir) {
        dir = getenv("HOME");
        if(0==dir) {
            errFatal("please  specify either env. variable HOME or BLOCKCHAIN_DIR");
        }
    }
    return getNormalizedDirName(
        dir              +
        std::string("/") +
        kCoinDirName
    );
}

static void findBlockFiles() {

    gChainSize = 0;

    auto blockChainDir = getBlockchainDir();
    auto blockDir = blockChainDir + std::string("/blocks");
    info("loading block chain from directory: %s", blockChainDir.c_str());

    struct stat statBuf;
    auto r = stat(blockDir.c_str(), &statBuf);
    auto oldStyle = (r<0 || !S_ISDIR(statBuf.st_mode));

    int blkDatId = (oldStyle ? 1 : 0);
    auto fmt = oldStyle ? "/blk%04d.dat" : "/blocks/blk%05d.dat";
    while(1) {

        char buf[64];
        sprintf(buf, fmt, blkDatId++);

        auto fileName = blockChainDir + std::string(buf) ;
        auto openFlags = O_RDONLY | O_BINARY;
        auto fd = open(fileName.c_str(), openFlags);
        if(fd<0) {
            if(1<blkDatId) {
                break;
            }
            sysErrFatal(
                "failed to open block chain file %s",
                fileName.c_str()
            );
        }

        struct stat statBuf;
        auto r0 = fstat(fd, &statBuf);
        if(r0<0) {
            sysErrFatal(
                "failed to fstat block chain file %s",
                fileName.c_str()
            );
        }

        auto fileSize = statBuf.st_size;
	#if !defined(_WIN64)
	    auto r1 = posix_fadvise(fd, 0, fileSize, POSIX_FADV_NOREUSE);
	    if(r1<0) {
		warning(
		    "failed to posix_fadvise on block chain file %s",
		    fileName.c_str()
		);
	    }
	#endif

        BlockFile blockFile;
        blockFile.fd = fd;
        blockFile.size = fileSize;
        blockFile.name = fileName;
        blockFiles.push_back(blockFile);
        gChainSize += fileSize;
    }
    info("block chain size = %.3f Gigs", 1e-9*gChainSize);
}

static void cleanBlockFiles() {
    for(const auto &blockFile : blockFiles) {
        auto r = close(blockFile.fd);
        if(r<0) {
            sysErr(
                "failed to close block chain file %s",
                blockFile.name.c_str()
            );
        }
    }
}

int main(
    int   argc,
    char *argv[]
) {

    parseGlobalArgs(argc, argv);

    auto start = Timer::usecs();
    fprintf(stderr, "\n");
    info("mem at start = %.3f Gigs", getMem());

    initCallback(argc, argv);
    findBlockFiles();
    initHashtables();
    buildNullBlock();
    buildBlockHeaders();
    computeBlockHeights();
    wireLongestChain();
    parseLongestChain();
    cleanBlockFiles();

    auto elapsed = (Timer::usecs() - start)*1e-6;
    info("all done in %.2f seconds", elapsed);
    info("mem at end = %.3f Gigs\n", getMem());
    return 0;
}

