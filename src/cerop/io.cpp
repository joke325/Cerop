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
#include "cerop/io.hpp"


CEROP_NAMESPACE_BEGIN {

RopInputT::RopInputT(const RopObjRef& parent, const RopHandle iid) : RopObjectT(parent.lock()) {
    Attach(iid);
    inputCB = nullptr;
    inpcbCtx = nullptr;
}

RopInputT::RopInputT(const RopObjRef& parent, InputCallBack* inputCB, void* app_ctx) : RopObjectT(parent.lock()) {
    this->inputCB = inputCB;
    this->inpcbCtx = app_ctx;
}

RopInputT::~RopInputT() {
    if(handle != nullptr) {
        try {
            Util::CheckError(CALL(rnp_input_destroy)(HCAST_INP(handle)));
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

RopData RopInputT::dump_packets_to_json(const bool mpi, const bool raw, const bool grip) { API_PROLOG
    unsigned flags = (mpi? RNP_JSON_DUMP_MPI : 0);
    flags |= (raw? RNP_JSON_DUMP_RAW : 0);
    flags |= (grip? RNP_JSON_DUMP_GRIP : 0);
    char *result = nullptr;
    unsigned ret = CALL(rnp_dump_packets_to_json)(HCAST_INP(handle), flags, &result);
    return Util::GetRopData(me, ret, result, Util::StrLen(result));
}
void RopInputT::dump_packets_to_output(const RopOutput& output, const bool mpi, const bool raw, const bool grip) { API_PROLOG
    unsigned flags = (mpi? RNP_DUMP_MPI : 0);
    flags |= (raw? RNP_DUMP_RAW : 0);
    flags |= (grip? RNP_DUMP_GRIP : 0);
    Util::CheckError(CALL(rnp_dump_packets_to_output)(HCAST_INP(handle), HCAST_OUTP(output->getHandle()), flags));
}
void RopInputT::enarmor(const RopOutput& output, const InString& type) { API_PROLOG
    Util::CheckError(CALL(rnp_enarmor)(HCAST_INP(handle), HCAST_OUTP(output->getHandle()), type));
}
void RopInputT::dearmor(const RopOutput& output) { API_PROLOG
    Util::CheckError(CALL(rnp_dearmor)(HCAST_INP(handle), HCAST_OUTP(output->getHandle())));
}
RopString RopInputT::guess_contents() { API_PROLOG
    char *contents = nullptr;
    return Util::GetRopString(me, CALL(rnp_guess_contents)(HCAST_INP(handle), &contents), &contents);
}


RopOutputT::RopOutputT(const RopObjRef& parent, const RopHandle oid) : RopObjectT(parent.lock()) {
    Attach(oid);
    outputCB = nullptr;
    outpcbCtx = nullptr;
}

RopOutputT::RopOutputT(const RopObjRef& parent, OutputCallBack* outputCB, void* app_ctx) : RopObjectT(parent.lock()) {
    this->outputCB = outputCB;
    this->outpcbCtx = app_ctx;
}

RopOutputT::~RopOutputT() {
    if(handle != nullptr) {
        try {
            unsigned ret = CALL(rnp_output_finish)(HCAST_OUTP(handle));
            unsigned ret2 = CALL(rnp_output_destroy)(HCAST_OUTP(handle));
            Util::CheckError(ret!=ROPE::SUCCESS? ret : ret2);
        } catch(std::exception&) {
            ForwardException(NEW_THROWED());
        }
        handle = nullptr;
    }
}

RopOutput RopOutputT::output_to_armor(const InString& type) { API_PROLOG
    rnp_output_t output = nullptr;
    RET_ROP_OBJECT(RopOutput, output, CALL(rnp_output_to_armor)(HCAST_OUTP(handle), &output, type));
}
RopData RopOutputT::memory_get_buf(const bool doCopy) { API_PROLOG
    uint8_t *buf = nullptr;
    size_t len = 0;
    unsigned ret = CALL(rnp_output_memory_get_buf)(HCAST_OUTP(handle), &buf, &len, doCopy);
    return Util::GetRopData(me, ret, buf, len, doCopy);
}
size_t RopOutputT::write(const RopDataT& data) { API_PROLOG
    size_t written = 0;
    Util::CheckError(CALL(rnp_output_write)(HCAST_OUTP(handle), data.getBuf(), data.getLen(), &written));
    return written;
}

} CEROP_NAMESPACE_END
