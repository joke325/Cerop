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

#include <string.h>
#include <algorithm>
#include "load.h"
#include "cerop/util.hpp"
#include "cerop/error.hpp"
#include "cerop/session.hpp"
#include "cerop/bind.hpp"


CEROP_NAMESPACE_BEGIN {

RopSessionT::RopSessionT(const RopObjRef& parent, const RopHandle sid) : RopObjectT(parent.lock()) {
    Attach(sid);
    passProvider = nullptr;
    keyProvider = nullptr;
}

RopSessionT::~RopSessionT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_ffi_destroy)(HCAST_FFI(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

RopBind RopSessionT::getBind() {
    return std::static_pointer_cast<RopBindT>(parent);
}

size_t RopSessionT::public_key_count() { API_PROLOG
    size_t count = 0;
    return Util::GetPrimVal<size_t>(CALL(rnp_get_public_key_count)(HCAST_FFI(handle), &count), &count);
}
size_t RopSessionT::secret_key_count() { API_PROLOG
    size_t count = 0;
    return Util::GetPrimVal<size_t>(CALL(rnp_get_secret_key_count)(HCAST_FFI(handle), &count), &count);
}

RopOpSign RopSessionT::op_sign_create(const RopInput& input, const RopOutput& output, const bool cleartext, const bool detached) { API_PROLOG
    unsigned ret = ROPE::SUCCESS;
    rnp_op_sign_t sign = nullptr;
    RopHandle inp = RopObjectT::getHandle(input);
    RopHandle outp = RopObjectT::getHandle(output);
    if(cleartext)
        ret = CALL(rnp_op_sign_cleartext_create)(&sign, HCAST_FFI(handle), HCAST_INP(inp), HCAST_OUTP(outp));
    else if(detached)
        ret = CALL(rnp_op_sign_detached_create)(&sign, HCAST_FFI(handle), HCAST_INP(inp), HCAST_OUTP(outp));
    else
        ret = CALL(rnp_op_sign_create)(&sign, HCAST_FFI(handle), HCAST_INP(inp), HCAST_OUTP(outp));
    RET_ROP_OBJECT2(RopOpSign, sign, ret, DEPEND_LIST(input, output));
}

RopOpGenerate RopSessionT::op_generate_create_subkey(const InString& keyAlg, const RopKey& primary) { API_PROLOG
    unsigned ret = ROPE::SUCCESS;
    rnp_op_generate_t op = nullptr;
    if(!primary)
        ret = CALL(rnp_op_generate_create)(&op, HCAST_FFI(handle), keyAlg);
    else
        ret = CALL(rnp_op_generate_subkey_create)(&op, HCAST_FFI(handle), HCAST_KEY(RopObjectT::getHandle(primary)), keyAlg);
    RET_ROP_OBJECT2(RopOpGenerate, op, ret, DEPEND_LIST(primary));
}

RopOpEncrypt RopSessionT::op_encrypt_create(const RopInput& input, const RopOutput& output) { API_PROLOG
    RopHandle inp = RopObjectT::getHandle(input);
    RopHandle outp = RopObjectT::getHandle(output);
    rnp_op_encrypt_t op = nullptr;
    unsigned ret = CALL(rnp_op_encrypt_create)(&op, HCAST_FFI(handle), HCAST_INP(inp), HCAST_OUTP(outp));
    RET_ROP_OBJECT2(RopOpEncrypt, op, ret, DEPEND_LIST(input, output));
}

RopOpVerify RopSessionT::op_verify_create(const RopInput& input, const RopOutput& output, const RopInput& signature) { API_PROLOG
    RopHandle inp = RopObjectT::getHandle(input);
    unsigned ret= ROPE::SUCCESS;
    rnp_op_verify_t op = nullptr;
    if(!signature) {
        RopHandle outp = RopObjectT::getHandle(output);
        ret = CALL(rnp_op_verify_create)(&op, HCAST_FFI(handle), HCAST_INP(inp), HCAST_OUTP(outp));
    } else {
        RopHandle sig = RopObjectT::getHandle(signature);
        ret = CALL(rnp_op_verify_detached_create)(&op, HCAST_FFI(handle), HCAST_INP(inp), HCAST_INP(sig));
    }
    RET_ROP_OBJECT2(RopOpVerify, op, ret, DEPEND_LIST(input, output));
}

void RopSessionT::load_keys(const InString& format, const RopInput& input, const bool pub, const bool sec) { API_PROLOG
    RopHandle inp = RopObjectT::getHandle(input);
    unsigned flags = (pub? RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
    flags |= (sec? RNP_LOAD_SAVE_SECRET_KEYS : 0);
    unsigned ret = CALL(rnp_load_keys)(HCAST_FFI(handle), format, HCAST_INP(inp), flags);
    Util::CheckError(ret);
}

void RopSessionT::unload_keys(const bool pub, const bool sec) { API_PROLOG
    unsigned flags = (pub? RNP_KEY_UNLOAD_PUBLIC : 0);
    flags |= (sec? RNP_KEY_UNLOAD_SECRET : 0);
    unsigned ret = CALL(rnp_unload_keys)(HCAST_FFI(handle), flags);
    Util::CheckError(ret);
}

RopKey RopSessionT::locate_key(const InString& identifier_type, const InString& identifier) { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_locate_key)(HCAST_FFI(handle), identifier_type, identifier, &key));
}
RopKey RopSessionT::generate_key_rsa(const uint32_t bits, const uint32_t subbits, const InString& userid, const InString& password) { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_generate_key_rsa)(HCAST_FFI(handle), bits, subbits, userid, password, &key));
}
RopKey RopSessionT::generate_key_dsa_eg(const uint32_t bits, const uint32_t subbits, const InString& userid, const InString& password) { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_generate_key_dsa_eg)(HCAST_FFI(handle), bits, subbits, userid, password, &key));
}
RopKey RopSessionT::generate_key_ec(const InString& curve, const InString& userid, const InString& password) { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_generate_key_ec)(HCAST_FFI(handle), curve, userid, password, &key));
}
RopKey RopSessionT::generate_key_25519(const InString& userid, const InString& password) { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_generate_key_25519)(HCAST_FFI(handle), userid, password, &key));
}
RopKey RopSessionT::generate_key_sm2(const InString& userid, const InString& password) { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_generate_key_sm2)(HCAST_FFI(handle), userid, password, &key));
}
RopKey RopSessionT::generate_key_ex(const InString& keyAlg, const InString& subAlg, const uint32_t keyBits, const uint32_t subBits, const InString& keyCurve, const InString& subCurve, const InString& userid, const InString& password) { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_generate_key_ex)(HCAST_FFI(handle), keyAlg, subAlg, keyBits, subBits, keyCurve, subCurve, userid, password, &key));
}
RopData RopSessionT::import_keys(const RopInput& input, const bool pub, const bool sec) { API_PROLOG
    char *results = nullptr;
    RopHandle inp = RopObjectT::getHandle(input);
    unsigned flags = (pub? RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
    flags |= (sec? RNP_LOAD_SAVE_SECRET_KEYS : 0);
    unsigned ret = CALL(rnp_import_keys)(HCAST_FFI(handle), HCAST_INP(inp), flags, &results);
    return Util::GetRopData(me, ret, results, Util::StrLen(results));
}

bool password_cb(void* ffi_, void* app_ctx, void* key_, const char* pgp_context, char buf[], size_t buf_len) {
    RopSessionT *ses = static_cast<RopSessionT*>(app_ctx);
    rnp_ffi_t ffi = static_cast<rnp_ffi_t>(ffi_);
    rnp_key_handle_t key = static_cast<rnp_key_handle_t>(key_);

    if(ses != nullptr && ses->passProvider != nullptr) {
        // create new Session and Key handlers
        try {
            RopSession ropSes(ffi!=nullptr? new RopSessionT(ses->parent, ffi) : nullptr);
            RopKey ropKey(key!=nullptr? new RopKeyT(ses->parent, key) : nullptr);
            SessionPassCallBack::Ret scbRet = ses->passProvider->PassCallBack(ropSes, ses->passcbCtx, ropKey, pgp_context, buf_len);
            if(ropSes)
                ropSes->Detach();
            if(ropKey)
                ropKey->Detach();
            if(scbRet.outBuf && buf_len > 0) {
                size_t len = std::min<size_t>(scbRet.outBuf->length(), buf_len-1);
                memcpy(buf, scbRet.outBuf->c_str(), len);
                buf[len] = '\0';
            }
            return scbRet.ret;
        } catch(RopError ex) {}
    }
    return false;
}
void RopSessionT::set_pass_provider(SessionPassCallBack* getpasscb, void* getpasscbCtx) { API_PROLOG
    this->passProvider = getpasscb;
    this->passcbCtx = getpasscbCtx;
    Util::CheckError(CALL(rnp_ffi_set_pass_provider)(HCAST_FFI(handle), reinterpret_cast<rnp_password_cb>(password_cb), getpasscb!=nullptr? this : nullptr));
}
RopIdIterator RopSessionT::identifier_iterator_create(const InString& identifier_type) { API_PROLOG
    rnp_identifier_iterator_t it = nullptr;
    RET_ROP_OBJECT(RopIdIterator, it, CALL(rnp_identifier_iterator_create)(HCAST_FFI(handle), &it, identifier_type));
}
void RopSessionT::set_log_fd(const int fd) { API_PROLOG
    unsigned ret = CALL(rnp_ffi_set_log_fd)(HCAST_FFI(handle), fd);
    Util::CheckError(ret);
}

void key_cb(void* ffi_, void* app_ctx, const char* identifier_type, const char* identifier, bool secret) {
    RopSessionT *ses = static_cast<RopSessionT*>(app_ctx);
    rnp_ffi_t ffi = static_cast<rnp_ffi_t>(ffi_);

    if(ses != nullptr && ses->keyProvider != nullptr) {
        // create a new Session handler
        try {
            RopSession ropSes(ffi!=nullptr? new RopSessionT(ses->parent, ffi) : nullptr);
            ses->keyProvider->KeyCallBack(ropSes, ses->keycbCtx, identifier_type, identifier, secret);
            if(ropSes)
                ropSes->Detach();
        } catch(RopError ex) {}
    }
}
void RopSessionT::set_key_provider(SessionKeyCallBack* keyProvider, void* getkeycbCtx) { API_PROLOG
    this->keyProvider = keyProvider;
    this->keycbCtx = getkeycbCtx;
    Util::CheckError(CALL(rnp_ffi_set_key_provider)(HCAST_FFI(handle), reinterpret_cast<rnp_get_key_cb>(key_cb), keyProvider!=nullptr? this : nullptr));
}
void RopSessionT::save_keys(const InString& format, const RopOutput& output, const bool pub, const bool sec) { API_PROLOG
    RopHandle outp = RopObjectT::getHandle(output);
    unsigned flags = (pub? RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
    flags |= (sec? RNP_LOAD_SAVE_SECRET_KEYS : 0);
    unsigned ret = CALL(rnp_save_keys)(HCAST_FFI(handle), format, HCAST_OUTP(outp), flags);
    Util::CheckError(ret);
}
RopData RopSessionT::generate_key_json(const RopDataT& json) { API_PROLOG
    char *results = nullptr;
    unsigned ret = CALL(rnp_generate_key_json)(HCAST_FFI(handle), (const char*)(json), &results);
    return Util::GetRopData(me, ret, results, Util::StrLen(results));
}
void RopSessionT::decrypt(const RopInput& input, const RopOutput& output) { API_PROLOG
    RopHandle inp = RopObjectT::getHandle(input);
    RopHandle outp = RopObjectT::getHandle(output);
    unsigned ret = CALL(rnp_decrypt)(HCAST_FFI(handle), HCAST_INP(inp), HCAST_OUTP(outp));
    Util::CheckError(ret);
}


RopIdIteratorT::RopIdIteratorT(const RopObjRef& parent, const RopHandle iid) : RopObjectT(parent.lock()) {
    Attach(iid);
}

RopIdIteratorT::~RopIdIteratorT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_op_verify_destroy)(HCAST_OPVER(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

RopString RopIdIteratorT::next() { API_PROLOG
    const char *identifier = nullptr;
    return Util::GetRopString(me, CALL(rnp_identifier_iterator_next)(HCAST_IDIT(handle), &identifier), &identifier, false);
}

} CEROP_NAMESPACE_END
