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

#ifndef ROP_KEY_H
#define ROP_KEY_H

#include "types.hpp"
#include "io.hpp"
#include "sign.hpp"


CEROP_NAMESPACE_BEGIN {

class RopUidHandleT;
typedef std::shared_ptr<RopUidHandleT> RopUidHandle;

class RopKeyT;
typedef std::shared_ptr<RopKeyT> RopKey;


class RopUidHandleT : public RopObjectT {
public:
    virtual ~RopUidHandleT();

    // API

    size_t signature_count();
    bool is_revoked();
    RopSign get_signature_at(const size_t idx);

protected:
    RopUidHandleT(const RopObjRef& parent, const RopHandle uid);

friend class RopKeyT;
};


class RopKeyT : public RopObjectT {
public:
    virtual ~RopKeyT();

    // API

    RopString keyid();
    RopString alg();
    RopString primary_grip();
    RopString fprint();
    RopString grip();
    RopString primary_uid();
    RopString curve();
    RopString revocation_reason();
    void set_expiration(const Duration& expiry);
    bool is_revoked();
    bool is_superseded();
    bool is_compromised();
    bool is_retired();
    bool is_locked();
    bool is_protected();
    bool is_primary();
    bool is_sub();
    bool have_secret();
    bool have_public();
    Instant creation();
    Duration expiration();
    size_t uid_count();
    size_t signature_count();
    uint32_t bits();
    uint32_t dsa_qbits();
    size_t subkey_count();
    RopString get_uid_at(const size_t idx);
    RopData to_json(const bool publicMpis = true, const bool secretMpis = true, const bool signatures = true, const bool signMpis = true);
    RopData packets_to_json(const bool secret = true, const bool mpi = true, const bool raw = true, const bool grip = true);
    bool allows_usage(const InString& usage);
    bool allows_usages(const StringsT& usages);
    bool disallows_usages(const StringsT& usages);
    void lock();
    void unlock(const InString& password);
    RopUidHandle get_uid_handle_at(const size_t idx);
    void protect(const InString& password, const InString& cipher, const InString& cipherMode, const InString& hash, const size_t iterations);
    void unprotect(const InString& password);
    RopData public_key_data();
    RopData secret_key_data();
    void add_uid(const InString& uid, const InString& hash, const Instant& expiration, const uint8_t keyFlags, const bool primary);
    RopKey get_subkey_at(const size_t idx);
    RopSign get_signature_at(const size_t idx);
    void export_key(const RopOutput& output, const bool pub = false, const bool sec = false, const bool subkey = false, const bool armored = false);
    inline void export_public(const RopOutput& output, const bool subkey = false, const bool armored = false) {
        return export_key(output, true, false, subkey, armored);
    }
    inline void export_secret(const RopOutput& output, const bool subkey = false, const bool armored = false) {
        return export_key(output, false, true, subkey, armored);
    }
    void export_revocation(const RopOutput& output, const InString& hash, const InString& code, const InString& reason);
    void revoke(const InString& hash, const InString& code, const InString& reason);
    void remove(const bool pub = false, const bool sec = false, const bool sub = false);
    inline void remove_public(const bool subkeys = false) {
        remove(true, false, subkeys);
    }
    inline void remove_secret(const bool subkeys = false) {
        remove(false, true, subkeys);
    }

protected:
    RopKeyT(const RopObjRef& parent, const RopHandle uid);

friend class RopSessionT;
friend class RopSignT;
friend class RopOpGenerateT;
friend class RopVeriSignatureT;
friend bool password_cb(void*, void*, void*, const char*, char*, size_t);
};

} CEROP_NAMESPACE_END

#endif // ROP_KEY_H
