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

#include <sstream>
#include <stdexcept>
#include "load.h"
#include "cerop/util.hpp"
#include "cerop/error.hpp"
#include "cerop/bind.hpp"


CEROP_NAMESPACE_BEGIN {

std::atomic_long RopBindT::instanceCnt(0);

RopBind RopBindT::New(const bool checkLibVer) {
    ROP_load();
    RopBindT *bind = new RopBindT();
    RopBind pBind(bind);
    bind->me = pBind;
    if(pBind)
        instanceCnt++;
    return  pBind;
}

RopBindT::RopBindT(const bool checkLibVer) : RopObjectT(RopObject()) {
    if(checkLibVer && !(CALL(rnp_version()) >= CALL(rnp_version_for(0, 9, 0))) && !(CALL(rnp_version_commit_timestamp)() >= ropid()))
        throw RopError(ROPE::ERROR_LIBVERSION);
}

RopBindT::~RopBindT() {
    instanceCnt--;
}

static StringT altHome;
RopString RopBindT::default_homedir() { API_PROLOG
    char *homedir = nullptr;
    unsigned err = CALL(rnp_get_default_homedir)(&homedir);
    if(err == ROPE::ERROR_NOT_SUPPORTED) {
        if(altHome.length() == 0 && getenv("HOMEDRIVE")) {
            altHome = StringT(getenv("HOMEDRIVE")) + getenv("HOMEPATH");
            altHome = altHome + (strchr(altHome.c_str(),'/')?"/":"\\") + ".rnp";
        }
        return RopString(new RopStringT(me, altHome.c_str(), false));
    }
    return Util::GetRopString(me, err, &homedir);
}
String RopBindT::version_string() { API_PROLOG
    const char *version = CALL(rnp_version_string)();
    return String(version!=nullptr? new StringT(version) : nullptr);
}
String RopBindT::version_string_full() { API_PROLOG
    const char *version = CALL(rnp_version_string_full)();
    return String(version!=nullptr? new StringT(version) : nullptr);
}
uint32_t RopBindT::version() { API_PROLOG
    return CALL(rnp_version)();
}
uint64_t RopBindT::version_commit_timestamp() { API_PROLOG
    return CALL(rnp_version_commit_timestamp)();
}
RopStrings RopBindT::get_homedir_info(const InString& homedir) { API_PROLOG
    char *info[] = { nullptr, nullptr, nullptr, nullptr };
    rnp_result_t res = CALL(rnp_detect_homedir_info)(homedir, info+0, info+1, info+2, info+3);
    RopStringsT *strs = new RopStringsT();
    strs->reserve(4);
    for(int idx = 0; idx < 4; idx++)
        strs->push_back(Util::GetRopString(me, res, info+idx));
    return RopStrings(strs);
}
uint32_t RopBindT::version_for(const uint32_t major, const uint32_t minor, const uint32_t patch) { API_PROLOG
    return CALL(rnp_version_for)(major, minor, patch);
}
uint32_t RopBindT::version_major(const uint32_t version) { API_PROLOG
    return CALL(rnp_version_major)(version);
}
uint32_t RopBindT::version_minor(const uint32_t version) { API_PROLOG
    return CALL(rnp_version_minor)(version);
}
uint32_t RopBindT::version_patch(const uint32_t version) { API_PROLOG
    return CALL(rnp_version_patch)(version);
}
String RopBindT::result_to_string(const uint32_t result) { API_PROLOG
    const char *str = CALL(rnp_result_to_string)(result);
    return String(str!=nullptr? new StringT(str) : nullptr);
}
uint32_t RopBindT::enable_debug(const InString& file) { API_PROLOG
    return CALL(rnp_enable_debug)(file);
}
uint32_t RopBindT::disable_debug() { API_PROLOG
    return CALL(rnp_disable_debug)();
}
bool RopBindT::supports_feature(const InString& type, const InString& name) { API_PROLOG
    bool supported = false;
    return Util::GetPrimVal<bool>(CALL(rnp_supports_feature)(type, name, &supported), &supported);
}
RopString RopBindT::supported_features(const InString& type) { API_PROLOG
    char *result = nullptr;
    return Util::GetRopString(me, CALL(rnp_supported_features)(type, &result), &result);
}
RopString RopBindT::detect_key_format(const RopDataT& buf) { API_PROLOG
    char *format = nullptr;
    return Util::GetRopString(me, CALL(rnp_detect_key_format)(static_cast<const uint8_t*>(buf.getBuf()), buf.getLen(), &format), &format);
}
size_t RopBindT::calculate_iterations(const InString& hash, const size_t msec) { API_PROLOG
    size_t iterations = 0;
    return Util::GetPrimVal<size_t>(CALL(rnp_calculate_iterations)(hash, msec, &iterations), &iterations);
}
RopSession RopBindT::create_session(const InString& pubFormat, const InString& secFormat) { API_PROLOG
    rnp_ffi_t ffi = nullptr;
    RET_ROP_OBJECT(RopSession, ffi, CALL(rnp_ffi_create)(&ffi, pubFormat, secFormat));
}
void RopBindT::buffer_clear(void *ptr, size_t size) { API_PROLOG
    CALL(rnp_buffer_clear)(ptr, size);
}
void RopBindT::buffer_clear(const String& str) { API_PROLOG
    if(str) {
        CALL(rnp_buffer_clear)(&(*str)[0], str->capacity());
        str->clear();
    }
}
RopInput RopBindT::create_input(const RopDataT& buf, const bool doCopy) { API_PROLOG
    rnp_input_t input = nullptr;
    RET_ROP_OBJECT(RopInput, input, CALL(rnp_input_from_memory)(&input, buf.getBBuf(), buf.getLen(), doCopy));
}
RopInput RopBindT::create_input(const InString& path) { API_PROLOG
    rnp_input_t input = nullptr;
    RET_ROP_OBJECT(RopInput, input, CALL(rnp_input_from_path)(&input, path));
}

bool input_reader(void *app_ctx, void *buf, size_t len, size_t *read) {
    RopInputT *inp = static_cast<RopInputT*>(app_ctx);
    if(inp != nullptr && inp->inputCB != nullptr)
        return inp->inputCB->ReadCallBack(inp->inpcbCtx, buf, len, read);
    return 0;
}
void input_closer(void *app_ctx) {
    RopInputT *inp = static_cast<RopInputT*>(app_ctx);
    if(inp != nullptr && inp->inputCB != nullptr)
        return inp->inputCB->RCloseCallBack(inp->inpcbCtx);
}
RopInput RopBindT::create_input(InputCallBack& inputCB, void* app_ctx) { API_PROLOG
    RopInput inp = RopInput(new RopInputT(me, &inputCB, app_ctx));
    inp->FeedBack(inp);
    rnp_input_t input = nullptr;
    Util::CheckError(CALL(rnp_input_from_callback)(&input, reinterpret_cast<rnp_input_reader_t*>(input_reader), input_closer, inp.get()));
    inp->Attach(input);
    return inp;
}
RopOutput RopBindT::create_output(const InString& toFile, const bool overwrite, const bool random) { API_PROLOG
    rnp_output_t output = nullptr;
    unsigned flags = (overwrite? RNP_OUTPUT_FILE_OVERWRITE : 0);
    flags |= (random? RNP_OUTPUT_FILE_RANDOM : 0);
    RET_ROP_OBJECT(RopOutput, output, CALL(rnp_output_to_file)(&output, toFile, flags));
}
RopOutput RopBindT::create_output(const InString& toPath) { API_PROLOG
    rnp_output_t output = nullptr;
    RET_ROP_OBJECT(RopOutput, output, CALL(rnp_output_to_path)(&output, toPath));
}
RopOutput RopBindT::create_output(const size_t maxAlloc) { API_PROLOG
    rnp_output_t output = nullptr;
    RET_ROP_OBJECT(RopOutput, output, CALL(rnp_output_to_memory)(&output, maxAlloc));
}
RopOutput RopBindT::create_output() { API_PROLOG
    rnp_output_t output = nullptr;
    RET_ROP_OBJECT(RopOutput, output, CALL(rnp_output_to_null)(&output));
}

bool output_writer(void *app_ctx, const void *buf, size_t len) {
    RopOutputT *outp = static_cast<RopOutputT*>(app_ctx);
    if(outp != nullptr && outp->outputCB != nullptr)
        return outp->outputCB->WriteCallBack(outp->outpcbCtx, buf, len);
    return false;
}
void output_closer(void *app_ctx, bool discard) {
    RopOutputT *outp = static_cast<RopOutputT*>(app_ctx);
    if(outp != nullptr && outp->outputCB != nullptr)
        outp->outputCB->WCloseCallBack(outp->outpcbCtx, discard);
}
RopOutput RopBindT::create_output(OutputCallBack& outputCB, void* app_ctx) { API_PROLOG
    RopOutput outp = RopOutput(new RopOutputT(me, &outputCB, app_ctx));
    outp->FeedBack(outp);
    rnp_output_t output = nullptr;
    Util::CheckError(CALL(rnp_output_to_callback)(&output, output_writer, output_closer, outp.get()));
    outp->Attach(output);
    return outp;
}

String RopBindT::toString() const {
    std::stringstream msg;
    msg << "use_count = " << me.use_count() << '\n' << "inst_count = " << instanceCnt << '\n';
    msg << "thl = " << (thl!=nullptr? thl->size() : 0) << '\n';
    return String(new StringT(msg.str()));
}

unsigned RopBindT::ropid() const { return 1610638124; }

const StringT RopBindT::KEYSTORE_GPG(RNP_KEYSTORE_GPG);
const StringT RopBindT::KEYSTORE_KBX(RNP_KEYSTORE_KBX);
const StringT RopBindT::KEYSTORE_G10(RNP_KEYSTORE_G10);
const StringT RopBindT::KEYSTORE_GPG21(RNP_KEYSTORE_GPG21);
const StringT RopBindT::ALG_HASH_MD5(RNP_ALGNAME_MD5);
const StringT RopBindT::ALG_HASH_SHA1(RNP_ALGNAME_SHA1);
const StringT RopBindT::ALG_HASH_SHA256(RNP_ALGNAME_SHA256);
const StringT RopBindT::ALG_HASH_SHA384(RNP_ALGNAME_SHA384);
const StringT RopBindT::ALG_HASH_SHA512(RNP_ALGNAME_SHA512);
const StringT RopBindT::ALG_HASH_SHA224(RNP_ALGNAME_SHA224);
const StringT RopBindT::ALG_HASH_SHA3_256(RNP_ALGNAME_SHA3_256);
const StringT RopBindT::ALG_HASH_SHA3_512(RNP_ALGNAME_SHA3_512);
const StringT RopBindT::ALG_HASH_RIPEMD160(RNP_ALGNAME_RIPEMD160);
const StringT RopBindT::ALG_HASH_SM3(RNP_ALGNAME_SM3);
const StringT RopBindT::ALG_HASH_DEFAULT(RopBindT::ALG_HASH_SHA256);
const StringT RopBindT::ALG_SYMM_IDEA(RNP_ALGNAME_IDEA);
const StringT RopBindT::ALG_SYMM_TRIPLEDES(RNP_ALGNAME_TRIPLEDES);
const StringT RopBindT::ALG_SYMM_CAST5(RNP_ALGNAME_CAST5);
const StringT RopBindT::ALG_SYMM_BLOWFISH(RNP_ALGNAME_BLOWFISH);
const StringT RopBindT::ALG_SYMM_TWOFISH(RNP_ALGNAME_TWOFISH);
const StringT RopBindT::ALG_SYMM_AES_128(RNP_ALGNAME_AES_128);
const StringT RopBindT::ALG_SYMM_AES_192(RNP_ALGNAME_AES_192);
const StringT RopBindT::ALG_SYMM_AES_256(RNP_ALGNAME_AES_256);
const StringT RopBindT::ALG_SYMM_CAMELLIA_128(RNP_ALGNAME_CAMELLIA_128);
const StringT RopBindT::ALG_SYMM_CAMELLIA_192(RNP_ALGNAME_CAMELLIA_192);
const StringT RopBindT::ALG_SYMM_CAMELLIA_256(RNP_ALGNAME_CAMELLIA_256);
const StringT RopBindT::ALG_SYMM_SM4(RNP_ALGNAME_SM4);
const StringT RopBindT::ALG_SYMM_DEFAULT(RopBindT::ALG_SYMM_AES_256);
const StringT RopBindT::ALG_ASYM_RSA(RNP_ALGNAME_RSA);
const StringT RopBindT::ALG_ASYM_ELGAMAL(RNP_ALGNAME_ELGAMAL);
const StringT RopBindT::ALG_ASYM_DSA(RNP_ALGNAME_DSA);
const StringT RopBindT::ALG_ASYM_ECDH(RNP_ALGNAME_ECDH);
const StringT RopBindT::ALG_ASYM_ECDSA(RNP_ALGNAME_ECDSA);
const StringT RopBindT::ALG_ASYM_EDDSA(RNP_ALGNAME_EDDSA);
const StringT RopBindT::ALG_ASYM_SM2(RNP_ALGNAME_SM2);
const StringT RopBindT::ALG_PLAINTEXT(RNP_ALGNAME_PLAINTEXT);
const StringT RopBindT::ALG_CRC24(RNP_ALGNAME_CRC24);

const int RopBindT::USER_ID = 1;
const int RopBindT::USER_ATTR = 2;

} CEROP_NAMESPACE_END


static void ThrowML(const char* libName, const char* err) {
    throw std::runtime_error(std::string("Missing library ")+libName+"\n"+err);
}
static void ThrowMM(const char* metName, const char* err) {
    throw std::runtime_error(std::string("Missing method ")+metName+"\n"+err);
}
extern "C" void ThrowMissingLibrary(const char* libName, const char* err) { ThrowML(libName, err); }
extern "C" void ThrowMissingMethod(const char* metName, const char* err) { ThrowMM(metName, err); }
