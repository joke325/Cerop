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

#include <string.h>
#include <cstdlib>
#include <iostream>
#include "load.h"
#include "cerop/types.hpp"
#include "cerop/util.hpp"
#include "cerop/error.hpp"


CEROP_NAMESPACE_BEGIN {

RopObjectT::RopObjectT(const RopObject& parent, const RopHandle handle) : parent(parent) {
    this->handle = handle;
deps = nullptr;
    thl = nullptr;
}

RopObjectT::~RopObjectT() {
    if(deps != nullptr) {
        delete deps;
        deps = nullptr;
    }
    if(thl != nullptr) {
        delete thl;
        thl = nullptr;
    }
}

void RopObjectT::Attach(const RopHandle handle) {
    if(handle == nullptr)
        throw RopError(ROPE::ERROR_NULL_HANDLE);
    this->handle = handle;
}

void RopObjectT::ForwardException(const RopThrowed& thr) {
    if(thl == nullptr)
        thl = new RopThrowList();
    if(thl != nullptr)
        thl->push_back(thr);
    if(parent != nullptr)
        parent->ForwardException(thr);
}

void RopObjectT::ExceptionCheck() {
    if(thl != nullptr) {
        while(thl->size() > 0 && thl->front()->handled)
            thl->erase(thl->begin());
        if(thl->size() > 0) {
            thl->front()->handled = true;
            std::rethrow_exception(thl->front()->ex);
        }
    }
}


RopBufferT::RopBufferT(const RopObjRef& parent, const void*const buf, const size_t len, const bool free) noexcept : 
    RopObjectT(parent.lock()), buf(buf), len(len), free(free) {}

RopBufferT::RopBufferT(const RopObjRef& parent, const char*const buf, const bool free) noexcept : 
    RopObjectT(parent.lock()), buf(buf), len(buf!=nullptr? strlen(buf) : 0), free(free) {}

RopBufferT::~RopBufferT() { 
    if(free) 
        try {
            CALL(rnp_buffer_destroy)(const_cast<void*>(buf));
        } catch(std::exception&) { ForwardException(NEW_THROWED()); } 
}


RopStringT::RopStringT(const RopObjRef& parent, const void*const buf, const size_t len, const bool free) noexcept : RopBufferT(parent, buf, len, free) {}

RopStringT::RopStringT(const RopObjRef& parent, const char*const str, const bool free) noexcept : RopBufferT(parent, str, free) {}

std::ostream& operator <<(std::ostream& outs, const RopString& str) {
    outs.write(static_cast<const char*>(str->buf), str->len);
    return outs;
}


RopDataT::RopDataT(const RopObjRef& parent, const void*const buf, const size_t len, const bool free) noexcept : RopStringT(parent, buf, len, free) {}

RopDataT::RopDataT(const void*const buf, const size_t len) noexcept : RopStringT(RopObjRef(), buf, len, false) {}

RopDataT::RopDataT(const char*const str) noexcept : RopStringT(RopObjRef(), str, false) {}

RopDataT::RopDataT(const StringT& str) noexcept : RopStringT(RopObjRef(), str.c_str(), str.size(), false) {}

std::ostream& operator <<(std::ostream& outs, const RopData& str) {
    outs.write(static_cast<const char*>(str->buf), str->len);
    return outs;
}

} CEROP_NAMESPACE_END
