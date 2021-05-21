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

/**
 * @version 0.3.0
 */

#include "load.h"
#include "cerop/error.hpp"
#include "cerop/util.hpp"
#include "cerop/key.hpp"
#include "cerop/op.hpp"


CEROP_NAMESPACE_BEGIN {

RopSignSignatureT::RopSignSignatureT(const RopObjRef& parent, const RopHandle sid) : RopObjectT(parent.lock()) {
    Attach(sid);
}

RopSignSignatureT::~RopSignSignatureT() {
    if(handle != nullptr) {
        handle = nullptr;
    }
}

void RopSignSignatureT::set_hash(const InString& hash) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_signature_set_hash)(HCAST_OPSSN(handle), hash));
}
void RopSignSignatureT::set_creation_time(const Instant& create) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_signature_set_creation_time)(HCAST_OPSSN(handle), Util::Datetime2TS(create)));
}
void RopSignSignatureT::set_expiration_time(const Instant& expires) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_signature_set_expiration_time)(HCAST_OPSSN(handle), Util::Datetime2TS(expires)));
}


RopOpSignT::RopOpSignT(const RopObjRef& parent, const RopHandle sid) : RopObjectT(parent.lock()) {
    Attach(sid);
}

RopOpSignT::~RopOpSignT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_op_sign_destroy)(HCAST_OPSIG(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

void RopOpSignT::set_compression(const InString& compression, const int level) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_compression)(HCAST_OPSIG(handle), compression, level));
}
void RopOpSignT::set_armor(const bool armored) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_armor)(HCAST_OPSIG(handle), armored));
}
void RopOpSignT::set_hash(const InString& hash) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_hash)(HCAST_OPSIG(handle), hash));
}
void RopOpSignT::set_creation_time(const Instant& create) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_creation_time)(HCAST_OPSIG(handle), Util::Datetime2TS(create)));
}
void RopOpSignT::set_expiration_time(const Instant& expire) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_expiration_time)(HCAST_OPSIG(handle), Util::Datetime2TS(expire)));
}
void RopOpSignT::set_expiration(const Duration& expire) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_expiration_time)(HCAST_OPSIG(handle), Util::TimeDelta2Sec(expire)));
}
void RopOpSignT::set_file_name(const InString& filename) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_file_name)(HCAST_OPSIG(handle), filename));
}
void RopOpSignT::set_file_mtime(const Instant& mtime) { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_set_file_mtime)(HCAST_OPSIG(handle), Util::Datetime2TS(mtime)));
}
void RopOpSignT::execute() { API_PROLOG
    Util::CheckError(CALL(rnp_op_sign_execute)(HCAST_OPSIG(handle)));
}
RopSignSignature RopOpSignT::add_signature(const RopKey& key) { API_PROLOG
    rnp_op_sign_signature_t sig = nullptr;
    RET_ROP_OBJECT(RopSignSignature, sig, CALL(rnp_op_sign_add_signature)(HCAST_OPSIG(handle), HCAST_KEY(RopObjectT::getHandle(key)), &sig));
}


RopOpGenerateT::RopOpGenerateT(const RopObjRef& parent, const RopHandle gid) : RopObjectT(parent.lock()) {
    Attach(gid);
}

RopOpGenerateT::~RopOpGenerateT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_op_generate_destroy)(HCAST_OPGEN(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

void RopOpGenerateT::set_bits(const uint32_t bits) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_bits)(HCAST_OPGEN(handle), bits));
}
void RopOpGenerateT::set_hash(const InString& hash) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_hash)(HCAST_OPGEN(handle), hash));
}
void RopOpGenerateT::set_dsa_qbits(const uint32_t qbits) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_dsa_qbits)(HCAST_OPGEN(handle), qbits));
}
void RopOpGenerateT::set_curve(const InString& curve) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_curve)(HCAST_OPGEN(handle), curve));
}
void RopOpGenerateT::set_protection_password(const InString& password) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_protection_password)(HCAST_OPGEN(handle), password));
}
void RopOpGenerateT::set_request_password(const bool request) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_request_password)(HCAST_OPGEN(handle), request));
}
void RopOpGenerateT::set_protection_cipher(const InString& cipher) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_protection_cipher)(HCAST_OPGEN(handle), cipher));
}
void RopOpGenerateT::set_protection_hash(const InString& hash) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_protection_hash)(HCAST_OPGEN(handle), hash));
}
void RopOpGenerateT::set_protection_mode(const InString& mode) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_protection_mode)(HCAST_OPGEN(handle), mode));
}
void RopOpGenerateT::set_protection_iterations(const uint32_t iterations) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_protection_iterations)(HCAST_OPGEN(handle), iterations));
}
void RopOpGenerateT::add_usage(const InString& usage) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_add_usage)(HCAST_OPGEN(handle), usage));
}
void RopOpGenerateT::clear_usage() { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_clear_usage)(HCAST_OPGEN(handle)));
}
void RopOpGenerateT::set_usages(const StringsT& usages) { API_PROLOG
    clear_usage();
    for(const StringT& usage : usages)
        add_usage(usage);
}
void RopOpGenerateT::set_userid(const InString& userid) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_userid)(HCAST_OPGEN(handle), userid));
}
void RopOpGenerateT::set_expiration(const Duration& expiration) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_expiration)(HCAST_OPGEN(handle), Util::TimeDelta2Sec(expiration)));
}
void RopOpGenerateT::add_pref_hash(const InString& hash) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_add_pref_hash)(HCAST_OPGEN(handle), hash));
}
void RopOpGenerateT::clear_pref_hashes() { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_clear_pref_hashes)(HCAST_OPGEN(handle)));
}
void RopOpGenerateT::set_pref_hashes(const StringsT& hashes) { API_PROLOG
    clear_pref_hashes();
    for(const StringT& hash : hashes)
        add_pref_hash(hash);
}
void RopOpGenerateT::add_pref_compression(const InString& compression) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_add_pref_compression)(HCAST_OPGEN(handle), compression));
}
void RopOpGenerateT::clear_pref_compression() { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_clear_pref_compression)(HCAST_OPGEN(handle)));
}
void RopOpGenerateT::set_pref_compressions(const StringsT& compressions) { API_PROLOG
    clear_pref_compression();
    for(const StringT& compression : compressions)
        add_pref_compression(compression);
}
void RopOpGenerateT::add_pref_cipher(const InString& cipher) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_add_pref_cipher)(HCAST_OPGEN(handle), cipher));
}
void RopOpGenerateT::clear_pref_ciphers() { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_clear_pref_ciphers)(HCAST_OPGEN(handle)));
}
void RopOpGenerateT::set_pref_ciphers(const StringsT& ciphers) { API_PROLOG
    clear_pref_ciphers();
    for(const StringT& cipher : ciphers)
        add_pref_cipher(cipher);
}
void RopOpGenerateT::set_pref_keyserver(const InString& keyserver) { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_set_pref_keyserver)(HCAST_OPGEN(handle), keyserver));
}
void RopOpGenerateT::execute() { API_PROLOG
    Util::CheckError(CALL(rnp_op_generate_execute)(HCAST_OPGEN(handle)));
}
RopKey RopOpGenerateT::get_key() { API_PROLOG
    rnp_key_handle_t hnd = nullptr;
    RET_ROP_OBJECT(RopKey, hnd, CALL(rnp_op_generate_get_key)(HCAST_OPGEN(handle), &hnd));
}


RopOpEncryptT::RopOpEncryptT(const RopObjRef& parent, const RopHandle eid) : RopObjectT(parent.lock(), eid) {
    Attach(eid);
}

RopOpEncryptT::~RopOpEncryptT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_op_encrypt_destroy)(HCAST_OPENC(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

void RopOpEncryptT::add_recipient(const RopKey& key) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_add_recipient)(HCAST_OPENC(handle), HCAST_KEY(RopObjectT::getHandle(key))));
}
RopSignSignature RopOpEncryptT::add_signature(const RopKey& key) { API_PROLOG
    rnp_op_sign_signature_t sig = nullptr;
    RET_ROP_OBJECT(RopSignSignature, sig, CALL(rnp_op_encrypt_add_signature)(HCAST_OPENC(handle), HCAST_KEY(RopObjectT::getHandle(key)), &sig));
}
void RopOpEncryptT::set_hash(const InString& hash) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_hash)(HCAST_OPENC(handle), hash));
}
void RopOpEncryptT::set_creation_time(const Instant& create) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_creation_time)(HCAST_OPENC(handle), Util::Datetime2TS(create)));
}
void RopOpEncryptT::set_expiration_time(const Instant& expire) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_expiration_time)(HCAST_OPENC(handle), Util::Datetime2TS(expire)));
}
void RopOpEncryptT::add_password(const InString& password, const InString& s2kHash, const size_t iterations, const InString& s2kCipher) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_add_password)(HCAST_OPENC(handle), password, s2kHash, iterations, s2kCipher));
}
void RopOpEncryptT::set_armor(const bool armored) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_armor)(HCAST_OPENC(handle), armored));
}
void RopOpEncryptT::set_cipher(const InString& cipher) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_cipher)(HCAST_OPENC(handle), cipher));
}
void RopOpEncryptT::set_aead(const InString& alg) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_aead)(HCAST_OPENC(handle), alg));
}
void RopOpEncryptT::set_aead_bits(const int bits) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_aead_bits)(HCAST_OPENC(handle), bits));
}
void RopOpEncryptT::set_compression(const InString& compression, const int level) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_compression)(HCAST_OPENC(handle), compression, level));
}
void RopOpEncryptT::set_file_name(const InString& filename) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_file_name)(HCAST_OPENC(handle), filename));
}
void RopOpEncryptT::set_file_mtime(const Instant& mtime) { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_set_file_mtime)(HCAST_OPENC(handle), Util::Datetime2TS(mtime)));
}
void RopOpEncryptT::execute() { API_PROLOG
    Util::CheckError(CALL(rnp_op_encrypt_execute)(HCAST_OPENC(handle)));
}


RopVeriSignatureT::RopVeriSignatureT(const RopObjRef& parent, const RopHandle vid) : RopObjectT(parent.lock(), vid) {
    Attach(vid);
}

RopVeriSignatureT::~RopVeriSignatureT() {
    if(handle != nullptr) {
        handle = nullptr;
    }
}

RopString RopVeriSignatureT::hash() { API_PROLOG
    char *hash = nullptr;
    return Util::GetRopString(me, CALL(rnp_op_verify_signature_get_hash)(HCAST_OPVES(handle), &hash), &hash);
}
unsigned RopVeriSignatureT::status() { API_PROLOG
    return CALL(rnp_op_verify_signature_get_status)(HCAST_OPVES(handle));
}
RopSign RopVeriSignatureT::get_handle() { API_PROLOG
    rnp_signature_handle_t hnd = nullptr;
    RET_ROP_OBJECT(RopSign, hnd, CALL(rnp_op_verify_signature_get_handle)(HCAST_OPVES(handle), &hnd));
}
RopKey RopVeriSignatureT::get_key() { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_op_verify_signature_get_key)(HCAST_OPVES(handle), &key));
}
Instants RopVeriSignatureT::get_times() { API_PROLOG
    uint32_t create = 0, expires = 0;
    Util::CheckError(CALL(rnp_op_verify_signature_get_times)(HCAST_OPVES(handle), &create, &expires));
    Instants inst(new InstantsT());
    inst->push_back(Instant(Duration(create)));
    inst->push_back(Instant(Duration(expires)));
    return inst;
}


RopRecipientT::RopRecipientT(const RopObjRef& parent, const RopHandle rid) : RopObjectT(parent.lock(), rid) {
    Attach(rid);
}

RopRecipientT::~RopRecipientT() {
    if(handle != nullptr) {
        handle = nullptr;
    }
}

RopString RopRecipientT::get_keyid() { API_PROLOG
    char *keyid = nullptr;
    return Util::GetRopString(me, CALL(rnp_recipient_get_keyid)(HCAST_RECIP(handle), &keyid), &keyid);
}
RopString RopRecipientT::get_alg() { API_PROLOG
    char *alg = nullptr;
    return Util::GetRopString(me, CALL(rnp_recipient_get_alg)(HCAST_RECIP(handle), &alg), &alg);
}


RopSymEncT::RopSymEncT(const RopObjRef& parent, const RopHandle eid) : RopObjectT(parent.lock(), eid) {
    Attach(eid);
}

RopSymEncT::~RopSymEncT() {
    if(handle != nullptr) {
        handle = nullptr;
    }
}

RopString RopSymEncT::get_cipher() { API_PROLOG
    char *cipher = nullptr;
    return Util::GetRopString(me, CALL(rnp_symenc_get_cipher)(HCAST_SENC(handle), &cipher), &cipher);
}
RopString RopSymEncT::get_aead_alg() { API_PROLOG
    char *alg = nullptr;
    return Util::GetRopString(me, CALL(rnp_symenc_get_aead_alg)(HCAST_SENC(handle), &alg), &alg);
}
RopString RopSymEncT::get_hash_alg() { API_PROLOG
    char *alg = nullptr;
    return Util::GetRopString(me, CALL(rnp_symenc_get_hash_alg)(HCAST_SENC(handle), &alg), &alg);
}
RopString RopSymEncT::get_s2k_type() { API_PROLOG
    char *type = nullptr;
    return Util::GetRopString(me, CALL(rnp_symenc_get_s2k_type)(HCAST_SENC(handle), &type), &type);
}
uint32_t RopSymEncT::get_s2k_iterations() { API_PROLOG
    uint32_t iterations = false;
    return Util::GetPrimVal<uint32_t>(CALL(rnp_symenc_get_s2k_iterations)(HCAST_SENC(handle), &iterations), &iterations);
}


RopOpVerifyT::RopOpVerifyT(const RopObjRef& parent, const RopHandle vid) : RopObjectT(parent.lock(), vid) {
    Attach(vid);
}

RopOpVerifyT::~RopOpVerifyT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_op_verify_destroy)(HCAST_OPVER(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

size_t RopOpVerifyT::signature_count() { API_PROLOG
    size_t count = false;
    return Util::GetPrimVal<size_t>(CALL(rnp_op_verify_get_signature_count)(HCAST_OPVER(handle), &count), &count);
}
void RopOpVerifyT::execute() { API_PROLOG
    Util::CheckError(CALL(rnp_op_verify_execute)(HCAST_OPVER(handle)));
}
RopVeriSignature RopOpVerifyT::get_signature_at(size_t idx) { API_PROLOG
    rnp_op_verify_signature_t sig = nullptr;
    RET_ROP_OBJECT(RopVeriSignature, sig, CALL(rnp_op_verify_get_signature_at)(HCAST_OPVER(handle), idx, &sig));
}
RopOpVerifyT::FileInfoP RopOpVerifyT::get_file_info() { API_PROLOG
    char *filename = nullptr;
    uint32_t mtime = 0;
    RopString fname = Util::GetRopString(me, CALL(rnp_op_verify_get_file_info)(HCAST_OPVER(handle), &filename, &mtime), &filename);
    return RopOpVerifyT::FileInfoP(new RopOpVerifyT::FileInfo((const char*)*fname, Instant(Duration(mtime))));
}
bool RopOpVerifyT::get_protection_info(RopString* mode, RopString* cipher) { API_PROLOG
    char *mod = nullptr, *cip = nullptr;
    char **pmod = (mode? &mod : nullptr), **pcip = (cipher? &cip : nullptr);
    bool valid = false;
    RopString modS = Util::GetRopString(me, CALL(rnp_op_verify_get_protection_info)(HCAST_OPVER(handle), pmod, pcip, &valid), pmod);
    RopString cipS = Util::GetRopString(me, ROPE::SUCCESS, pcip);
    if(mode) *mode = modS;
    if(cipher) *cipher = cipS;
    return valid;
}
RopOpVerifyT::ProtectionInfo RopOpVerifyT::get_protection_info() {
    RopOpVerifyT::ProtectionInfo info;
    info.valid = get_protection_info(&info.mode, &info.cipher);
    return info;
}
size_t RopOpVerifyT::get_recipient_count() { API_PROLOG
    size_t count = false;
    return Util::GetPrimVal<size_t>(CALL(rnp_op_verify_get_recipient_count)(HCAST_OPVER(handle), &count), &count);
}
RopRecipient RopOpVerifyT::get_used_recipient() { API_PROLOG
    rnp_recipient_handle_t hnd = nullptr;
    RET_ROP_OBJECT(RopRecipient, hnd, CALL(rnp_op_verify_get_used_recipient)(HCAST_OPVER(handle), &hnd));
}
RopRecipient RopOpVerifyT::get_recipient_at(const size_t idx) { API_PROLOG
    rnp_recipient_handle_t hnd = nullptr;
    RET_ROP_OBJECT(RopRecipient, hnd, CALL(rnp_op_verify_get_recipient_at)(HCAST_OPVER(handle), idx, &hnd));
}
size_t RopOpVerifyT::get_symenc_count() { API_PROLOG
    size_t count = false;
    return Util::GetPrimVal<size_t>(CALL(rnp_op_verify_get_symenc_count)(HCAST_OPVER(handle), &count), &count);
}
RopSymEnc RopOpVerifyT::get_used_symenc() { API_PROLOG
    rnp_symenc_handle_t hnd = nullptr;
    RET_ROP_OBJECT(RopSymEnc, hnd, CALL(rnp_op_verify_get_used_symenc)(HCAST_OPVER(handle), &hnd));
}
RopSymEnc RopOpVerifyT::get_symenc_at(const size_t idx) { API_PROLOG
    rnp_symenc_handle_t hnd = nullptr;
    RET_ROP_OBJECT(RopSymEnc, hnd, CALL(rnp_op_verify_get_symenc_at)(HCAST_OPVER(handle), idx, &hnd));
}

} CEROP_NAMESPACE_END
