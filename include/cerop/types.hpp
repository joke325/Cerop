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

#ifndef ROP_TYPES_H
#define ROP_TYPES_H

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <ostream>
#include <stdexcept>


#define CEROP_NAMESPACE_BEGIN  namespace tech { namespace janky { namespace cerop
#define CEROP_NAMESPACE_END  } }
#define CEROP_NAMESPACE tech::janky::cerop
#define interface struct

CEROP_NAMESPACE_BEGIN {
   
typedef void* RopHandle;
    
typedef std::string StringT;
typedef std::vector<StringT> StringsT;
typedef std::shared_ptr<StringT> String;
typedef std::shared_ptr<StringsT> Strings;

class RopObjectT;
typedef std::shared_ptr<RopObjectT> RopObject;
typedef std::weak_ptr<RopObjectT> RopObjRef;
typedef std::vector<RopObject> RopObjects;

struct RopThrowedT {
    std::exception_ptr ex;
    bool handled;
    inline RopThrowedT(const std::exception_ptr& ex) : ex(ex) { handled = false; }
};
typedef std::shared_ptr<RopThrowedT> RopThrowed;
typedef std::vector<RopThrowed> RopThrowList;
 
class RopObjectT {
public:
    virtual ~RopObjectT();
    
    inline RopHandle getHandle() const noexcept { return handle; }
    inline void Detach() noexcept { handle = nullptr; }

    inline static RopHandle getHandle(const RopObjectT* obj) noexcept { return obj!=nullptr? obj->getHandle() : nullptr; }
    inline static RopHandle getHandle(const RopObject& obj) noexcept { return obj? obj->getHandle() : nullptr; }

    void ExceptionCheck();

protected:
    RopObjectT(const RopObject& parent, const RopHandle handle = nullptr);
    inline void FeedBack(const RopObject& obj, const std::shared_ptr<RopObjects>& depObjs = nullptr) noexcept { 
        me = obj; 
        if(depObjs) deps = new RopObjects(*depObjs); 
    }
    void Attach(const RopHandle handle);
    void ForwardException(const RopThrowed& thr);

    const RopObject parent;
    RopHandle handle;
    RopObjRef me;
    RopObjects *deps;
    RopThrowList *thl;
};


class RopBufferT : public RopObjectT {
public:
    RopBufferT(const RopObjRef& parent, const void*const buf, const size_t len, const bool free = true) noexcept;
    RopBufferT(const RopObjRef& parent, const char*const buf, const bool free = true) noexcept;
    virtual ~RopBufferT();

    inline const void* getBuf() const noexcept { return buf; }
    inline const uint8_t* getBBuf() const noexcept { return static_cast<const uint8_t*>(buf); }
    inline const size_t getLen() const noexcept { return len; }
    inline void setClear() noexcept { clear = true; }

protected:
    const void *const buf;
    const size_t len;
    const bool free;
    bool clear;
};

typedef std::shared_ptr<RopBufferT> RopBuffer;
class RopStringT;
typedef std::shared_ptr<RopStringT> RopString;
typedef std::vector<RopString> RopStringsT;
typedef std::shared_ptr<RopStringsT> RopStrings;

class RopStringT : public RopBufferT {
public:
    RopStringT(const RopObjRef& parent, const void*const buf, const size_t len, const bool free = true) noexcept;
    RopStringT(const RopObjRef& parent, const char*const str, const bool free = true) noexcept;
    inline operator String() const { return String(buf!=nullptr? new StringT(static_cast<const char*>(buf), len) : nullptr); }
    inline operator const char*() const { return static_cast<const char*>(buf); }
friend std::ostream& operator <<(std::ostream&, const RopString&);
};
std::ostream& operator <<(std::ostream& outs, const RopString& str);

class RopDataT;
typedef std::shared_ptr<RopDataT> RopData;

class RopDataT : public RopStringT {
public:
    RopDataT(const RopObjRef& parent, const void*const buf, const size_t len, const bool free = true) noexcept;
    RopDataT(const void*const buf, const size_t len) noexcept;
    RopDataT(const char*const str) noexcept;
    RopDataT(const StringT& str) noexcept;
friend std::ostream& operator <<(std::ostream&, const RopData&);
};
std::ostream& operator <<(std::ostream& outs, const RopData& str);

struct InString {
    inline InString(const char *cstr) noexcept : cstr(cstr) { type = CStr; }
    inline InString(const StringT& str) noexcept : str(&str) { type = Str; }
    inline InString(const RopStringT& rstr) noexcept : rstr(&rstr) { type = RStr; }
    union {
        const char *cstr;
        const StringT *str;
        const RopStringT *rstr;
    };
    enum StrType { CStr, Str, RStr };
    StrType type;
    inline operator const char*() const noexcept { 
        switch(type) { 
        case Str: return str!=nullptr? str->c_str() : (const char*)nullptr; break;
        case RStr: return rstr!=nullptr? *rstr : (const char*)nullptr; break;
        default: ;
        }
        return cstr;
    }
};

typedef std::chrono::duration<uint32_t> Duration;
typedef std::chrono::time_point<std::chrono::system_clock, Duration> Instant;
typedef std::vector<Instant> InstantsT;
typedef std::shared_ptr<InstantsT> Instants;

} CEROP_NAMESPACE_END

#endif // ROP_TYPES_H
