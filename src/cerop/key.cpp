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

#include "load.h"
#include "cerop/error.hpp"
#include "cerop/util.hpp"
#include "cerop/key.hpp"


CEROP_NAMESPACE_BEGIN {

RopUidHandleT::RopUidHandleT(const RopObjRef& parent, const RopHandle uid) : RopObjectT(parent.lock()) {
    Attach(uid);
}

RopUidHandleT::~RopUidHandleT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_uid_handle_destroy)(HCAST_UID(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

size_t RopUidHandleT::signature_count() { API_PROLOG
    size_t count = 0;
    return Util::GetPrimVal<size_t>(CALL(rnp_uid_get_signature_count)(HCAST_UID(handle), &count), &count);
}
bool RopUidHandleT::is_revoked() { API_PROLOG
    bool result = false;
    return Util::GetPrimVal<bool>(CALL(rnp_uid_is_revoked)(HCAST_UID(handle), &result), &result);
}
RopSign RopUidHandleT::get_signature_at(const size_t idx) { API_PROLOG
    rnp_signature_handle_t sig = nullptr;
    RET_ROP_OBJECT(RopSign, sig, CALL(rnp_uid_get_signature_at)(HCAST_UID(handle), idx, &sig));
}

RopKeyT::RopKeyT(const RopObjRef& parent, const RopHandle kid) : RopObjectT(parent.lock()) {
    Attach(kid);
}

RopKeyT::~RopKeyT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_key_handle_destroy)(HCAST_KEY(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

#define RET_KEY_STRING(nm, fx) \
    char *nm = nullptr; \
    return Util::GetRopString(me, CALL(fx)(HCAST_KEY(handle), &nm), &nm)
#define RET_KEY_PRIM(type, nm, def, fx) \
    type nm = def; \
    return Util::GetPrimVal<type>(CALL(fx)(HCAST_KEY(handle), &nm), &nm)
#define RET_KEY_BOOL(nm, fx) RET_KEY_PRIM(bool, nm, false, fx)
#define RET_KEY_SIZE(nm, fx) RET_KEY_PRIM(size_t, nm, 0, fx)
#define RET_KEY_U32(nm, fx) RET_KEY_PRIM(uint32_t, nm, 0, fx)

RopString RopKeyT::keyid() { API_PROLOG
    RET_KEY_STRING(keyid, rnp_key_get_keyid);
}
RopString RopKeyT::alg() { API_PROLOG
    RET_KEY_STRING(alg, rnp_key_get_alg);
}
RopString RopKeyT::primary_grip() { API_PROLOG
    RET_KEY_STRING(grip, rnp_key_get_primary_grip);
}
RopString RopKeyT::fprint() { API_PROLOG
    RET_KEY_STRING(fprint, rnp_key_get_fprint);
}
RopString RopKeyT::grip() { API_PROLOG
    RET_KEY_STRING(grip, rnp_key_get_grip);
}
RopString RopKeyT::primary_uid() { API_PROLOG
    RET_KEY_STRING(uid, rnp_key_get_primary_uid);
}
RopString RopKeyT::curve() { API_PROLOG
    RET_KEY_STRING(curve, rnp_key_get_curve);
}
RopString RopKeyT::revocation_reason() { API_PROLOG
    RET_KEY_STRING(result, rnp_key_get_revocation_reason);
}
bool RopKeyT::is_revoked() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_revoked);
}
bool RopKeyT::is_superseded() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_superseded);
}
bool RopKeyT::is_compromised() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_compromised);
}
bool RopKeyT::is_retired() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_retired);
}
bool RopKeyT::is_locked() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_locked);
}
bool RopKeyT::is_protected() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_protected);
}
bool RopKeyT::is_primary() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_primary);
}
bool RopKeyT::is_sub() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_is_sub);
}
bool RopKeyT::have_secret() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_have_secret);
}
bool RopKeyT::have_public() { API_PROLOG
    RET_KEY_BOOL(result, rnp_key_have_public);
}
Instant RopKeyT::creation() { API_PROLOG
    uint32_t result = 0;
    Util::GetPrimVal<uint32_t>(CALL(rnp_key_get_creation)(HCAST_KEY(handle), &result), &result);
    return Instant(Duration(result));
}
Duration RopKeyT::expiration() { API_PROLOG
    uint32_t result = 0;
    Util::GetPrimVal<uint32_t>(CALL(rnp_key_get_expiration)(HCAST_KEY(handle), &result), &result);
    return Duration(result);
}
size_t RopKeyT::uid_count() { API_PROLOG
    RET_KEY_SIZE(count, rnp_key_get_uid_count);
}
size_t RopKeyT::signature_count() { API_PROLOG
    RET_KEY_SIZE(count, rnp_key_get_signature_count);
}
uint32_t RopKeyT::bits() { API_PROLOG
    RET_KEY_U32(bits, rnp_key_get_bits);
}
uint32_t RopKeyT::dsa_qbits() { API_PROLOG
    RET_KEY_U32(qbits, rnp_key_get_dsa_qbits);
}
size_t RopKeyT::subkey_count() { API_PROLOG
    RET_KEY_SIZE(count, rnp_key_get_subkey_count);
}
RopString RopKeyT::get_uid_at(const size_t idx) { API_PROLOG
    char *uid = nullptr;
    return Util::GetRopString(me, CALL(rnp_key_get_uid_at)(HCAST_KEY(handle), idx, &uid), &uid);
}
RopData RopKeyT::to_json(const bool publicMpis, const bool secretMpis, const bool signatures, const bool signMpis) { API_PROLOG
    unsigned flags = (publicMpis? RNP_JSON_PUBLIC_MPIS : 0);
    flags |= (secretMpis? RNP_JSON_SECRET_MPIS : 0);
    flags |= (signatures? RNP_JSON_SIGNATURES : 0);
    flags |= (signMpis? RNP_JSON_SIGNATURE_MPIS : 0);
    char *result = nullptr;
    unsigned ret = CALL(rnp_key_to_json)(HCAST_KEY(handle), flags, &result);
    return Util::GetRopData(me, ret, result, Util::StrLen(result));
}
RopData RopKeyT::packets_to_json(const bool secret, const bool mpi, const bool raw, const bool grip) { API_PROLOG
    unsigned flags = (mpi? RNP_JSON_DUMP_MPI : 0);
    flags |= (raw? RNP_JSON_DUMP_RAW : 0);
    flags |= (grip? RNP_JSON_DUMP_GRIP : 0);
    char *result = nullptr;
    unsigned ret = CALL(rnp_key_packets_to_json)(HCAST_KEY(handle), secret, flags, &result);
    return Util::GetRopData(me, ret, result, Util::StrLen(result));
}
bool RopKeyT::allows_usage(const InString& usage) { API_PROLOG
    bool result = false; \
    return Util::GetPrimVal<bool>(CALL(rnp_key_allows_usage)(HCAST_KEY(handle), usage, &result), &result);
}
bool RopKeyT::allows_usages(const StringsT& usages) { API_PROLOG
    for(const StringT& usage : usages)
        if(!allows_usage(usage))
            return false;
    return true;
}
bool RopKeyT::disallows_usages(const StringsT& usages) { API_PROLOG
    for(const StringT& usage : usages)
        if(allows_usage(usage))
            return false;
    return true;
}
void RopKeyT::lock() { API_PROLOG
    Util::CheckError(CALL(rnp_key_lock)(HCAST_KEY(handle)));
}
void RopKeyT::unlock(const InString& password) { API_PROLOG
    Util::CheckError(CALL(rnp_key_unlock)(HCAST_KEY(handle), password));
}
RopUidHandle RopKeyT::get_uid_handle_at(const size_t idx) { API_PROLOG
    rnp_uid_handle_t uid = nullptr;
    RET_ROP_OBJECT(RopUidHandle, uid, CALL(rnp_key_get_uid_handle_at)(HCAST_KEY(handle), idx, &uid));
}
void RopKeyT::protect(const InString& password, const InString& cipher, const InString& cipherMode, const InString& hash, const size_t iterations) { API_PROLOG
    Util::CheckError(CALL(rnp_key_protect)(HCAST_KEY(handle), password, cipher, cipherMode, hash, iterations));
}
void RopKeyT::unprotect(const InString& password) { API_PROLOG
    Util::CheckError(CALL(rnp_key_unprotect)(HCAST_KEY(handle), password));
}
RopData RopKeyT::public_key_data() { API_PROLOG
    uint8_t *buf = nullptr;
    size_t buf_len = 0;
    unsigned ret = CALL(rnp_get_public_key_data)(HCAST_KEY(handle), &buf, &buf_len);
    return Util::GetRopData(me, ret, buf, buf_len);
}
RopData RopKeyT::secret_key_data() { API_PROLOG
    uint8_t *buf = nullptr;
    size_t buf_len = 0;
    unsigned ret = CALL(rnp_get_secret_key_data)(HCAST_KEY(handle), &buf, &buf_len);
    return Util::GetRopData(me, ret, buf, buf_len);
}
void RopKeyT::add_uid(const InString& uid, const InString& hash, const Instant& expiration, const uint8_t keyFlags, const bool primary) { API_PROLOG
    Util::CheckError(CALL(rnp_key_add_uid)(HCAST_KEY(handle), uid, hash, Util::Datetime2TS(expiration), keyFlags, primary));
}
RopKey RopKeyT::get_subkey_at(const size_t idx) { API_PROLOG
    rnp_key_handle_t subkey = nullptr;
    RET_ROP_OBJECT(RopKey, subkey, CALL(rnp_key_get_subkey_at(HCAST_KEY(handle), idx, &subkey)));
}
RopSign RopKeyT::get_signature_at(const size_t idx) { API_PROLOG
    rnp_signature_handle_t sig = nullptr;
    RET_ROP_OBJECT(RopSign, sig, CALL(rnp_key_get_signature_at(HCAST_KEY(handle), idx, &sig)));
}
void RopKeyT::export_key(const RopOutput& output, const bool pub, const bool sec, const bool subkey, const bool armored) { API_PROLOG
    RopHandle outp = RopObjectT::getHandle(output);
    unsigned flags = (pub? RNP_KEY_EXPORT_PUBLIC : 0);
    flags |= (sec? RNP_KEY_EXPORT_SECRET : 0);
    flags |= (subkey? RNP_KEY_EXPORT_SUBKEYS : 0);
    flags |= (armored? RNP_KEY_EXPORT_ARMORED : 0);
    Util::CheckError(CALL(rnp_key_export)(HCAST_KEY(handle), HCAST_OUTP(outp), flags));
}
void RopKeyT::remove(const bool pub, const bool sec) { API_PROLOG
    unsigned flags = (pub? RNP_KEY_REMOVE_PUBLIC : 0);
    flags |= (sec? RNP_KEY_REMOVE_SECRET : 0);
    Util::CheckError(CALL(rnp_key_remove(HCAST_KEY(handle), flags)));
}

} CEROP_NAMESPACE_END
