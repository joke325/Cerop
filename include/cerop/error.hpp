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

#ifndef ROP_ERROR_H
#define ROP_ERROR_H

#include <exception>
#include "types.hpp"


CEROP_NAMESPACE_BEGIN {

/** 
 * An Error Exception
 * @version 0.21
 * @since   0.21
 */
class RopError : public std::exception {
public:
    unsigned getErrCode() const;

    virtual const char* what() const noexcept override;

protected:
    RopError(const unsigned errCode) noexcept;

    StringT message;
    int errCode;

friend class RopBindT;
friend class RopSessionT;
friend class RopInputT;
friend class RopOutputT;
friend class RopUidHandleT;
friend class RopKeyT;
friend class RopSignT;
friend class RopSignSignatureT;
friend class RopOpSignT;
friend class RopOpGenerateT;
friend class RopOpEncryptT;
friend class RopVeriSignatureT;
friend class RopOpVerifyT;
friend class RopIdIteratorT;
friend class RopObjectT;
friend class Util;
};


class ROPE {
public:
    // Common error codes
    static const unsigned SUCCESS;
    static const unsigned ERROR_GENERIC;
    static const unsigned ERROR_BAD_FORMAT;
    static const unsigned ERROR_BAD_PARAMETERS;
    static const unsigned ERROR_NOT_IMPLEMENTED;
    static const unsigned ERROR_NOT_SUPPORTED;
    static const unsigned ERROR_OUT_OF_MEMORY;
    static const unsigned ERROR_SHORT_BUFFER;
    static const unsigned ERROR_NULL_POINTER;

    // Storage
    static const unsigned ERROR_ACCESS;
    static const unsigned ERROR_READ;
    static const unsigned ERROR_WRITE;

    // Crypto
    static const unsigned ERROR_BAD_STATE;
    static const unsigned ERROR_MAC_INVALID;
    static const unsigned ERROR_SIGNATURE_INVALID;
    static const unsigned ERROR_KEY_GENERATION;
    static const unsigned ERROR_BAD_PASSWORD;
    static const unsigned ERROR_KEY_NOT_FOUND;
    static const unsigned ERROR_NO_SUITABLE_KEY;
    static const unsigned ERROR_DECRYPT_FAILED;
    static const unsigned ERROR_RNG;
    static const unsigned ERROR_SIGNING_FAILED;
    static const unsigned ERROR_NO_SIGNATURES_FOUND;
    static const unsigned ERROR_SIGNATURE_EXPIRED;
    static const unsigned ERROR_VERIFICATION_FAILED;

    // Parsing
    static const unsigned ERROR_NOT_ENOUGH_DATA;
    static const unsigned ERROR_UNKNOWN_TAG;
    static const unsigned ERROR_PACKET_NOT_CONSUMED;
    static const unsigned ERROR_NO_USERID;
    static const unsigned ERROR_EOF;

    // ROP Errors
    static const unsigned ERROR_LIBVERSION;
    static const unsigned ERROR_INTERNAL;
    static const unsigned ERROR_NULL_HANDLE;
};

} CEROP_NAMESPACE_END

#endif // ROP_ERROR_H
