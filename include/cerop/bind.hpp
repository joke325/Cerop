/**
 * Copyright (c) 2020 Janky <box@janky.tech>
 * All right reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ROP_BIND_H
#define ROP_BIND_H

#include <memory>
#include <atomic>
#include "types.hpp"
#include "session.hpp"


CEROP_NAMESPACE_BEGIN {

class RopBindT;
typedef std::shared_ptr<RopBindT> RopBind;

#define NewRopBind RopBindT::New
    
/**
 * Root object of bindings for the RNP OpenPGP library
 * @version 0.21
 * @since   0.21
 */
class RopBindT : public RopObjectT {
public:
    static RopBind New(const bool checkLibVer = true);

    virtual ~RopBindT();

    // API

    RopString default_homedir();
    String version_string();
    String version_string_full();
    uint32_t version();
    uint64_t version_commit_timestamp();
    RopStrings get_homedir_info(const InString& homedir);
    uint32_t version_for(const uint32_t major, const uint32_t minor, const uint32_t patch);
    uint32_t version_major(const uint32_t version);
    uint32_t version_minor(const uint32_t version);
    uint32_t version_patch(const uint32_t version);
    String result_to_string(const uint32_t result);
    uint32_t enable_debug(const InString& file);
    uint32_t disable_debug();
    bool supports_feature(const InString& type, const InString& name);
    RopString supported_features(const InString& type);
    RopString detect_key_format(const RopDataT& buf);
    size_t calculate_iterations(const InString& hash, const size_t msec);
    RopSession create_session(const InString& pubFormat, const InString& secFormat);
    void buffer_clear(void *ptr, size_t size);
    void buffer_clear(const String& str);

    RopInput create_input(const RopDataT& buf, const bool doCopy);
    RopInput create_input(const InString& path);
    RopInput create_input(InputCallBack& inputCB, void* app_ctx);

    RopOutput create_output(const InString& toFile, const bool overwrite, const bool random);
    RopOutput create_output(const InString& toPath);
    RopOutput create_output(const size_t maxAlloc);
    RopOutput create_output();
    RopOutput create_output(OutputCallBack& outputCB, void* app_ctx);

    /**
     * Describes this object
     */
    String toString() const;
    unsigned ropid() const;

    // Constants

    static const StringT KEYSTORE_GPG;
    static const StringT KEYSTORE_KBX;
    static const StringT KEYSTORE_G10;
    static const StringT KEYSTORE_GPG21;

    static const StringT ALG_HASH_MD5;
    static const StringT ALG_HASH_SHA1;
    static const StringT ALG_HASH_SHA256;
    static const StringT ALG_HASH_SHA384;
    static const StringT ALG_HASH_SHA512;
    static const StringT ALG_HASH_SHA224;
    static const StringT ALG_HASH_SHA3_256;
    static const StringT ALG_HASH_SHA3_512;
    static const StringT ALG_HASH_RIPEMD160;
    static const StringT ALG_HASH_SM3;
    static const StringT ALG_HASH_DEFAULT;
    static const StringT ALG_SYMM_IDEA;
    static const StringT ALG_SYMM_TRIPLEDES;
    static const StringT ALG_SYMM_CAST5;
    static const StringT ALG_SYMM_BLOWFISH;
    static const StringT ALG_SYMM_TWOFISH;
    static const StringT ALG_SYMM_AES_128;
    static const StringT ALG_SYMM_AES_192;
    static const StringT ALG_SYMM_AES_256;
    static const StringT ALG_SYMM_CAMELLIA_128;
    static const StringT ALG_SYMM_CAMELLIA_192;
    static const StringT ALG_SYMM_CAMELLIA_256;
    static const StringT ALG_SYMM_SM4;
    static const StringT ALG_SYMM_DEFAULT;
    static const StringT ALG_ASYM_RSA;
    static const StringT ALG_ASYM_ELGAMAL;
    static const StringT ALG_ASYM_DSA;
    static const StringT ALG_ASYM_ECDH;
    static const StringT ALG_ASYM_ECDSA;
    static const StringT ALG_ASYM_EDDSA;
    static const StringT ALG_ASYM_SM2;
    static const StringT ALG_PLAINTEXT;
    static const StringT ALG_CRC24;

protected:
 
    /** 
     * Constructor
     */
    RopBindT(const bool checkLibVer = true);

    static std::atomic_long instanceCnt;
};

} CEROP_NAMESPACE_END

#endif //ROP_BIND_H
