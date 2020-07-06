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

#ifndef ROP_OP_H
#define ROP_OP_H

#include "types.hpp"
#include "sign.hpp"


CEROP_NAMESPACE_BEGIN {

class RopKeyT;
typedef std::shared_ptr<RopKeyT> RopKey;

class RopSignSignatureT;
typedef std::shared_ptr<RopSignSignatureT> RopSignSignature;

class RopOpSignT;
typedef std::shared_ptr<RopOpSignT> RopOpSign;

class RopOpGenerateT;
typedef std::shared_ptr<RopOpGenerateT> RopOpGenerate;

class RopOpEncryptT;
typedef std::shared_ptr<RopOpEncryptT> RopOpEncrypt;

class RopVeriSignatureT;
typedef std::shared_ptr<RopVeriSignatureT> RopVeriSignature;

class RopRecipientT;
typedef std::shared_ptr<RopRecipientT> RopRecipient;

class RopSymEncT;
typedef std::shared_ptr<RopSymEncT> RopSymEnc;

class RopOpVerifyT;
typedef std::shared_ptr<RopOpVerifyT> RopOpVerify;


class RopSignSignatureT : public RopObjectT {
public:
    virtual ~RopSignSignatureT();

    // API
    
    void set_hash(const InString& hash);
    void set_creation_time(const Instant& create);
    void set_expiration_time(const Instant& expires);

protected:
    RopSignSignatureT(const RopObjRef& parent, const RopHandle sid);

friend class RopOpSignT;
friend class RopOpEncryptT;
};


class RopOpSignT : public RopObjectT {
public:
    virtual ~RopOpSignT();

    // API

    void set_compression(const InString& compression, const int level);
    void set_armor(const bool armored);
    void set_hash(const InString& hash);
    void set_creation_time(const Instant& create);
    void set_expiration_time(const Instant& expire);
    void set_expiration(const Duration& expire);
    void set_file_name(const InString& filename);
    void set_file_mtime(const Instant& mtime);
    void execute();
    RopSignSignature add_signature(const RopKey& key);

protected:
    RopOpSignT(const RopObjRef& parent, const RopHandle sid);

friend class RopSessionT;
};


class RopOpGenerateT : public RopObjectT {
public:
    virtual ~RopOpGenerateT();

    // API

    void set_bits(const uint32_t bits);
    void set_hash(const InString& hash);
    void set_dsa_qbits(const uint32_t qbits);
    void set_curve(const InString& curve);
    void set_protection_password(const InString& password);
    void set_request_password(const bool request);
    void set_protection_cipher(const InString& cipher);
    void set_protection_hash(const InString& hash);
    void set_protection_mode(const InString& mode);
    void set_protection_iterations(const uint32_t iterations);
    void add_usage(const InString& usage);
    void clear_usage();
    void set_usages(const StringsT& usages);
    void set_userid(const InString& userid);
    void set_expiration(const Duration& expiration);
    void add_pref_hash(const InString& hash);
    void clear_pref_hashes();
    void set_pref_hashes(const StringsT& hashes);
    void add_pref_compression(const InString& compression);
    void clear_pref_compression();
    void set_pref_compressions(const StringsT& compressions);
    void add_pref_cipher(const InString& cipher);
    void clear_pref_ciphers();
    void set_pref_ciphers(const StringsT& ciphers);
    void set_pref_keyserver(const InString& keyserver);
    void execute();
    RopKey get_key();

protected:
    RopOpGenerateT(const RopObjRef& parent, const RopHandle gid);

friend class RopSessionT;
};


class RopOpEncryptT : public RopObjectT {
public:
    virtual ~RopOpEncryptT();

    // API

    void add_recipient(const RopKey& key);
    RopSignSignature add_signature(const RopKey& key);
    void set_hash(const InString& hash);
    void set_creation_time(const Instant& create);
    void set_expiration_time(const Instant& expire);
    void add_password(const InString& password, const InString& s2kHash, const size_t iterations, const InString& s2kCipher);
    void set_armor(const bool armored);
    void set_cipher(const InString& cipher);
    void set_aead(const InString& alg);
    void set_aead_bits(const int bits);
    void set_compression(const InString& compression, const int level);
    void set_file_name(const InString& filename);
    void set_file_mtime(const Instant& mtime);
    void execute();

protected:
    RopOpEncryptT(const RopObjRef& parent, const RopHandle eid);

friend class RopSessionT;
};


class RopVeriSignatureT : public RopObjectT {
public:
    virtual ~RopVeriSignatureT();

    // API

    RopString hash();
    unsigned status();
    RopSign get_handle();
    RopKey get_key();
    Instants get_times();

protected:
    RopVeriSignatureT(const RopObjRef& parent, const RopHandle vid);

friend class RopOpVerifyT;
};


class RopRecipientT : public RopObjectT {
public:
    virtual ~RopRecipientT();

    // API
    RopString get_keyid();
    RopString get_alg();

protected:
    RopRecipientT(const RopObjRef& parent, const RopHandle rid);

friend class RopOpVerifyT;
};


class RopSymEncT : public RopObjectT {
public:
    virtual ~RopSymEncT();

    // API
    RopString get_cipher();
    RopString get_aead_alg();
    RopString get_hash_alg();
    RopString get_s2k_type();
    uint32_t get_s2k_iterations();

protected:
    RopSymEncT(const RopObjRef& parent, const RopHandle rid);

friend class RopOpVerifyT;
};


class RopOpVerifyT : public RopObjectT {
public:
    virtual ~RopOpVerifyT();
    
    struct FileInfo {
        inline FileInfo(const StringT& fileName, const Instant& mtime) : fileName(fileName), mtime(mtime) {};
        StringT fileName;
        Instant mtime;
    };
    typedef std::shared_ptr<FileInfo> FileInfoP;
    
    // API

    size_t signature_count();
    void execute();
    RopVeriSignature get_signature_at(size_t idx);
    FileInfoP get_file_info();
    bool get_protection_info(RopString* mode, RopString* cipher);
    size_t get_recipient_count();
    RopRecipient get_used_recipient();
    RopRecipient get_recipient_at(const size_t idx);
    size_t get_symenc_count();
    RopSymEnc get_used_symenc();
    RopSymEnc get_symenc_at(const size_t idx);

protected:
    RopOpVerifyT(const RopObjRef& parent, const RopHandle vid);

friend class RopSessionT;
};

} CEROP_NAMESPACE_END

#endif // ROP_OP_H
