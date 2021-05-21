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
 * @version 0.14.0
 */

#include <string>
#include <sstream>
#include "load.h"
#include "cerop/error.hpp"


CEROP_NAMESPACE_BEGIN {

RopError::RopError(const unsigned errCode) noexcept {
    this->errCode = errCode;
    std::stringstream msg;
    msg << "ROP Error " << std::hex << errCode;
    message = msg.str();
}

unsigned RopError::getErrCode() const {
    return errCode;
}

const char* RopError::what() const noexcept {
    return message.c_str();
}

const unsigned ROPE::SUCCESS = RNP_SUCCESS;
const unsigned ROPE::ERROR_GENERIC = RNP_ERROR_GENERIC;
const unsigned ROPE::ERROR_BAD_FORMAT = RNP_ERROR_BAD_FORMAT;
const unsigned ROPE::ERROR_BAD_PARAMETERS = RNP_ERROR_BAD_PARAMETERS;
const unsigned ROPE::ERROR_NOT_IMPLEMENTED = RNP_ERROR_NOT_IMPLEMENTED;
const unsigned ROPE::ERROR_NOT_SUPPORTED = RNP_ERROR_NOT_SUPPORTED;
const unsigned ROPE::ERROR_OUT_OF_MEMORY = RNP_ERROR_OUT_OF_MEMORY;
const unsigned ROPE::ERROR_SHORT_BUFFER = RNP_ERROR_SHORT_BUFFER;
const unsigned ROPE::ERROR_NULL_POINTER = RNP_ERROR_NULL_POINTER;
const unsigned ROPE::ERROR_ACCESS = RNP_ERROR_ACCESS;
const unsigned ROPE::ERROR_READ = RNP_ERROR_READ;
const unsigned ROPE::ERROR_WRITE = RNP_ERROR_WRITE;
const unsigned ROPE::ERROR_BAD_STATE = RNP_ERROR_BAD_STATE;
const unsigned ROPE::ERROR_MAC_INVALID = RNP_ERROR_MAC_INVALID;
const unsigned ROPE::ERROR_SIGNATURE_INVALID = RNP_ERROR_SIGNATURE_INVALID;
const unsigned ROPE::ERROR_KEY_GENERATION = RNP_ERROR_KEY_GENERATION;
const unsigned ROPE::ERROR_BAD_PASSWORD = RNP_ERROR_BAD_PASSWORD;
const unsigned ROPE::ERROR_KEY_NOT_FOUND = RNP_ERROR_KEY_NOT_FOUND;
const unsigned ROPE::ERROR_NO_SUITABLE_KEY = RNP_ERROR_NO_SUITABLE_KEY;
const unsigned ROPE::ERROR_DECRYPT_FAILED = RNP_ERROR_DECRYPT_FAILED;
const unsigned ROPE::ERROR_RNG = RNP_ERROR_RNG;
const unsigned ROPE::ERROR_SIGNING_FAILED = RNP_ERROR_SIGNING_FAILED;
const unsigned ROPE::ERROR_NO_SIGNATURES_FOUND = RNP_ERROR_NO_SIGNATURES_FOUND;
const unsigned ROPE::ERROR_SIGNATURE_EXPIRED = RNP_ERROR_SIGNATURE_EXPIRED;
const unsigned ROPE::ERROR_VERIFICATION_FAILED = RNP_ERROR_VERIFICATION_FAILED;
const unsigned ROPE::ERROR_NOT_ENOUGH_DATA = RNP_ERROR_NOT_ENOUGH_DATA;
const unsigned ROPE::ERROR_UNKNOWN_TAG = RNP_ERROR_UNKNOWN_TAG;
const unsigned ROPE::ERROR_PACKET_NOT_CONSUMED = RNP_ERROR_PACKET_NOT_CONSUMED;
const unsigned ROPE::ERROR_NO_USERID = RNP_ERROR_NO_USERID;
const unsigned ROPE::ERROR_EOF = RNP_ERROR_EOF;

const unsigned ROPE::ERROR_LIBVERSION = 0x80000001;
const unsigned ROPE::ERROR_INTERNAL = 0x80000002;
const unsigned ROPE::ERROR_NULL_HANDLE = 0x80000003;

} CEROP_NAMESPACE_END
