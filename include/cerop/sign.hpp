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

#ifndef ROP_SIGN_H
#define ROP_SIGN_H

#include "types.hpp"


CEROP_NAMESPACE_BEGIN {

class RopSignT;
typedef std::shared_ptr<RopSignT> RopSign;

class RopKeyT;
typedef std::shared_ptr<RopKeyT> RopKey;


class RopSignT : public RopObjectT {
public:
    virtual ~RopSignT();

    // API

    RopString alg();
    RopString hash_alg();
    Instant creation();
    RopString keyid();
    RopKey get_signer();
    RopData to_json(const bool mpi = false, const bool raw = false, const bool grip = false);

protected:
    RopSignT(const RopObjRef& parent, const RopHandle sid);

friend class RopKeyT;
friend class RopUidHandleT;
friend class RopVeriSignatureT;
friend class RopOpVerifyT;
};

} CEROP_NAMESPACE_END

#endif // ROP_SIGN_H
