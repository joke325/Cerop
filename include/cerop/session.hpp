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

#ifndef ROP_SESSION_H
#define ROP_SESSION_H

#include <memory>
#include "types.hpp"
#include "io.hpp"
#include "key.hpp"
#include "op.hpp"


CEROP_NAMESPACE_BEGIN {

class RopSessionT;
typedef std::shared_ptr<RopSessionT> RopSession;

class RopIdIteratorT;
typedef std::shared_ptr<RopIdIteratorT> RopIdIterator;

class RopBindT;
typedef std::shared_ptr<RopBindT> RopBind;
    
interface SessionPassCallBack;
interface SessionKeyCallBack;
    
    
/**
 * Wraps FFI related ops
 * @version 0.2
 * @since   0.2
 */
class RopSessionT : public RopObjectT {
public:
    virtual ~RopSessionT();

    RopBind getBind();

    // API

    size_t public_key_count();
    size_t secret_key_count();
    RopOpSign op_sign_create(const RopInput& input, const RopOutput& output, const bool cleartext = false, const bool detached = false);
    inline RopOpSign op_sign_create_cleartext(const RopInput& input, const RopOutput& output) {
        return op_sign_create(input, output, true, false);
    }
    inline RopOpSign op_sign_create_detached(const RopInput& input, const RopOutput& output) {
        return op_sign_create(input, output, false, true);
    }

    RopOpGenerate op_generate_create_subkey(const InString& keyAlg, const RopKey& primary = RopKey(nullptr));
    inline RopOpGenerate op_generate_create(const InString& keyAlg) {
        return op_generate_create_subkey(keyAlg);
    }
    RopOpEncrypt op_encrypt_create(const RopInput& input, const RopOutput& output);
    RopOpVerify op_verify_create(const RopInput& input, const RopOutput& output, const RopInput& signature = RopInput(nullptr));
    inline RopOpVerify op_verify_create(const RopInput& input, const RopInput& signature) {
        return op_verify_create(input, RopOutput(nullptr), signature);
    }
    void load_keys(const InString& format, const RopInput& input, const bool pub = false, const bool sec = false);
    inline void load_keys_public(const InString& format, const RopInput& input) {
        load_keys(format, input, true, false);
    }
    inline void load_keys_secret(const InString& format, const RopInput& input) {
        load_keys(format, input, false, true);
    }
    void unload_keys(const bool pub = false, const bool sec = false);
    inline void unload_keys_public() {
        unload_keys(true, false);
    }
    inline void unload_keys_secret() {
        unload_keys(false, true);
    }
    RopKey locate_key(const InString& identifier_type, const InString& identifier);
    RopKey generate_key_rsa(const uint32_t bits, const uint32_t subbits, const InString& userid, const InString& password);
    RopKey generate_key_dsa_eg(const uint32_t bits, const uint32_t subbits, const InString& userid, const InString& password);
    RopKey generate_key_ec(const InString& curve, const InString& userid, const InString& password);
    RopKey generate_key_25519(const InString& userid, const InString& password);
    RopKey generate_key_sm2(const InString& userid, const InString& password);
    RopKey generate_key_ex(const InString& keyAlg, const InString& subAlg, const uint32_t keyBits, const uint32_t subBits, const InString& keyCurve, const InString& subCurve, const InString& userid, const InString& password);
    RopData import_keys(const RopInput& input, const bool pub = false, const bool sec = false);
    inline RopData import_keys_public(const RopInput& input) {
        return import_keys(input, true, false);
    }
    inline RopData import_keys_secret(const RopInput& input) {
        return import_keys(input, false, true);
    }
    void set_pass_provider(SessionPassCallBack* getpasscb, void* getpasscbCtx);
    RopIdIterator identifier_iterator_create(const InString& identifier_type);
    void set_log_fd(const int fd);
    void set_key_provider(SessionKeyCallBack* getkeycb, void* getkeycbCtx);
    void save_keys(const InString& format, const RopOutput& output, const bool pub = false, const bool sec = false);
    inline void save_keys_public(const InString& format, const RopOutput& output) {
        save_keys(format, output, true, false);
    }
    inline void save_keys_secret(const InString& format, const RopOutput& output) {
        save_keys(format, output, false, true);
    }
    RopData generate_key_json(const RopDataT& json);
    void decrypt(const RopInput& input, const RopOutput& output);

protected:
    RopSessionT(const RopObjRef& parent, const RopHandle sid);
    
    SessionPassCallBack *passProvider;
    void *passcbCtx;
    SessionKeyCallBack *keyProvider;
    void *keycbCtx;

friend class RopBindT;
friend bool password_cb(void*, void*, void*, const char*, char*, size_t);
friend void key_cb(void*, void*, const char*, const char*, bool);
};


class RopIdIteratorT : public RopObjectT {
public:
    virtual ~RopIdIteratorT();

    // API

    RopString next();

protected:
    RopIdIteratorT(const RopObjRef& parent, const RopHandle iid);

friend class RopSessionT;
};


interface SessionPassCallBack {
    struct Ret {
        inline Ret(const bool ret, const char* outBuf, const size_t len = 0) : ret(ret), outBuf(new StringT(outBuf, len>0? len : strlen(outBuf))) {}
        inline Ret(const bool ret, const String& outBuf) : ret(ret), outBuf(outBuf) {}
        bool ret;
        String outBuf;
    };
    virtual Ret PassCallBack(const RopSession& ses, void* ctx, const RopKey& key, const InString& pgpCtx, const size_t bufLen) = 0;
};


interface SessionKeyCallBack {
    virtual void KeyCallBack(const RopSession& ses, void* ctx, const InString& identifier_type, const InString& identifier, const bool secret) = 0;
};

} CEROP_NAMESPACE_END

#endif // ROP_SESSION_H
