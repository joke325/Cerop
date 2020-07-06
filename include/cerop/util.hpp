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

#ifndef ROP_UTIL_H
#define ROP_UTIL_H

#include <cstring>
#include "types.hpp"
#include "error.hpp"


CEROP_NAMESPACE_BEGIN {

/**
 * @version 0.21
 * @since   0.21
 */
class Util final {
public:
    static RopString GetRopString(const RopObjRef& parent, const int ret, const char*const*const ropStr, const bool freeBuf = true);
    static RopData GetRopData(const RopObjRef& parent, const int ret, const void*const ropBuf, const size_t bufLen, const bool freeBuf = true);
    inline static void CheckError(const unsigned ret) {
        if(ret != ROPE::SUCCESS)
            throw RopError(ret);
    }
    template<class T>
    inline static T GetPrimVal(const unsigned ret, const T*const val) {
        Util::CheckError(ret);
        return *val;
    }
    inline static size_t StrLen(const char* str) noexcept { return str!=nullptr? std::strlen(str) : 0; }
    inline static uint32_t Datetime2TS(const Instant& dtime) { 
        return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(dtime.time_since_epoch()).count());
    }
    inline static uint32_t TimeDelta2Sec(const Duration& tdtime) {
        return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(tdtime).count());
    }
    inline static uint32_t TimeNow() { 
        return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(Instant::clock::now().time_since_epoch()).count());
    }
};

#define RET_ROP_OBJECT2(Type, hnd, FX, dps) \
    Util::CheckError(FX); \
    Type obj = Type(new Type##T(me, hnd)); \
    obj->FeedBack(obj, dps); \
    return obj
#define RET_ROP_OBJECT(Type, hnd, FX) RET_ROP_OBJECT2(Type, hnd, FX, nullptr)
#define DEPEND_LIST(...) std::shared_ptr<RopObjects>(new RopObjects {__VA_ARGS__})
#define NEW_THROWED() RopThrowed(new RopThrowedT(std::current_exception()))
#define API_PROLOG if(thl) ExceptionCheck();

} CEROP_NAMESPACE_END

#endif // ROP_UTIL_H
