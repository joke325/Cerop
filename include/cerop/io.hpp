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

#ifndef ROP_IO_H
#define ROP_IO_H

#include <memory>
#include "types.hpp"


CEROP_NAMESPACE_BEGIN {

class RopInputT;
typedef std::shared_ptr<RopInputT> RopInput;

class RopOutputT;
typedef std::shared_ptr<RopOutputT> RopOutput;

interface InputCallBack {
    virtual size_t ReadCallBack(void *ctx, void *buf, size_t len) = 0;
    virtual void RCloseCallBack(void *ctx) = 0;
};

interface OutputCallBack {
    virtual bool WriteCallBack(void *ctx, const void *buf, size_t len) = 0;
    virtual void WCloseCallBack(void *ctx, bool discard) = 0;
};


class RopInputT : public RopObjectT {
public:
    virtual ~RopInputT();
    
    // API

    RopData dump_packets_to_json(const bool mpi = false, const bool raw = false, const bool grip = false);
    inline RopData dump_packets_to_json_mpi() {
        return dump_packets_to_json(true, false, false);
    }
    inline RopData dump_packets_to_json_raw() {
        return dump_packets_to_json(false, true, false);
    }
    inline RopData dump_packets_to_json_grip() {
        return dump_packets_to_json(false, false, true);
    }
    void dump_packets_to_output(const RopOutput& output, const bool mpi = false, const bool raw = false, const bool grip = false);
    inline void dump_packets_to_output_mpi(const RopOutput& output) {
        dump_packets_to_output(output, true, false, false);
    }
    inline void dump_packets_to_output_raw(const RopOutput& output) {
        dump_packets_to_output(output, false, true, false);
    }
    inline void dump_packets_to_output_grip(const RopOutput& output){
        dump_packets_to_output(output, false, false, true);
    }
    void enarmor(const RopOutput& output, const InString& type);
    void dearmor(const RopOutput& output);
    RopString guess_contents();
    
protected:
    RopInputT(const RopObjRef& parent, const RopHandle iid);
    RopInputT(const RopObjRef& parent, InputCallBack* inputCB, void* app_ctx);

    InputCallBack *inputCB;
    void *inpcbCtx;

friend class RopBindT;
friend size_t input_reader(void*, void*, size_t);
friend void input_closer(void*);
};


class RopOutputT : public RopObjectT {
public:
    virtual ~RopOutputT();

    // API

    RopOutput output_to_armor(const InString& type);
    RopData memory_get_buf(const bool doCopy);
    size_t write(const RopDataT& data);

protected:
    RopOutputT(const RopObjRef& parent, const RopHandle oid);
    RopOutputT(const RopObjRef& parent, OutputCallBack* outputCB, void* app_ctx);

    OutputCallBack *outputCB;
    void *outpcbCtx;

friend class RopBindT;
friend bool output_writer(void*, const void*, size_t);
friend void output_closer(void*, bool);
};

} CEROP_NAMESPACE_END

#endif // ROP_IO_H
