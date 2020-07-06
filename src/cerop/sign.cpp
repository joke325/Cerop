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
 * @version 0.2.1
 */

#include "load.h"
#include "cerop/error.hpp"
#include "cerop/util.hpp"
#include "cerop/key.hpp"
#include "cerop/sign.hpp"


CEROP_NAMESPACE_BEGIN {

RopSignT::RopSignT(const RopObjRef& parent, const RopHandle sid) : RopObjectT(parent.lock()) {
    Attach(sid);
}

RopSignT::~RopSignT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_signature_handle_destroy)(HCAST_SIG(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }

}

RopString RopSignT::alg() { API_PROLOG
    char *alg = nullptr;
    return Util::GetRopString(me, CALL(rnp_signature_get_alg)(HCAST_SIG(handle), &alg), &alg);
}
RopString RopSignT::hash_alg() { API_PROLOG
    char *alg = nullptr;
    return Util::GetRopString(me, CALL(rnp_signature_get_hash_alg)(HCAST_SIG(handle), &alg), &alg);
}
Instant RopSignT::creation() { API_PROLOG
    uint32_t create = 0;
    Util::CheckError(CALL(rnp_signature_get_creation)(HCAST_SIG(handle), &create));
    return Instant(Duration(create));
}
RopString RopSignT::keyid() { API_PROLOG
    char *result = nullptr;
    return Util::GetRopString(me, CALL(rnp_signature_get_keyid)(HCAST_SIG(handle), &result), &result);
}
RopKey RopSignT::get_signer() { API_PROLOG
    rnp_key_handle_t key = nullptr;
    RET_ROP_OBJECT(RopKey, key, CALL(rnp_signature_get_signer)(HCAST_SIG(handle), &key));
}
RopData RopSignT::to_json(const bool mpi, const bool raw, const bool grip) { API_PROLOG
    unsigned flags = (mpi? RNP_JSON_DUMP_MPI : 0);
    flags |= (raw? RNP_JSON_DUMP_RAW : 0);
    flags |= (grip? RNP_JSON_DUMP_GRIP : 0);
    char *json = nullptr;
    unsigned ret = CALL(rnp_signature_packet_to_json)(HCAST_SIG(handle), flags, &json);
    return Util::GetRopData(me, ret, json, Util::StrLen(json));
}

} CEROP_NAMESPACE_END
