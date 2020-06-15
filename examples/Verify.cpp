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

#include <iostream>
#include <exception>
#include "Verify.hpp"


// an example key provider
void Verify::KeyCallBack(const RopSession& ses, void* ctx, const InString& identifier_type, const InString& identifier, const bool secret) {
    if(strcmp(identifier_type, "keyid") == 0) {
        std::string filename = std::string("key-") + (const char*)identifier + "-" + (secret? "sec" : "pub") + ".asc";
        std::string err_desc;
        try {
            RopBind rop = ses->getBind();
            err_desc = std::string("failed to open key file ") + filename;
            RopInput input = rop->create_input(filename);

            err_desc = std::string("failed to load key from file ") + filename;
            ses->load_keys(RopBindT::KEYSTORE_GPG, input, true, true);
        } catch(RopError&) {
            std::cout << err_desc << std::endl;
            throw;
        }
    }
}

void Verify::verify(RopBind& rop) {
    try {
        // initialize
        RopSession ses = rop->create_session(RopBindT::KEYSTORE_GPG, RopBindT::KEYSTORE_GPG);

        // we do not load any keys here since we'll use key provider
        ses->set_key_provider(this, nullptr);

        std::string err_desc;
        RopOutput output;
        try {
            // create file input and memory output objects for the signed message
            // and verified message
            err_desc = "Failed to open file 'signed.asc'. Did you run the sign example?";
            RopInput input = rop->create_input("signed.asc");

            err_desc = "Failed to create output object";
            output = rop->create_output(0);

            err_desc = "Failed to create verification context";
            RopOpVerify verify = ses->op_verify_create(input, output);

            err_desc = "Failed to execute verification operation";
            verify->execute();

            // now check signatures and get some info about them
            err_desc = "Failed to get signature count";
            int sigcount = verify->signature_count();

            for(int idx = 0; idx < sigcount; idx++) {
                err_desc = std::string("Failed to get signature ") + std::to_string(idx);
                RopVeriSignature sig = verify->get_signature_at(idx);

                err_desc = std::string("failed to get signature's ") + std::to_string(idx) + "key";
                RopKey key = sig->get_key();

                err_desc = std::string("failed to get key id ") + std::to_string(idx);

                std::cout << "Status for signature from key " << key->keyid() << " : " << sig->status() << std::endl;
            }
        } catch(RopError&) {
            std::cout << err_desc << std::endl;
            throw;
        }

        // get the verified message from the output structure
        RopData buf = output->memory_get_buf(false);
        std::cout << "Verified message: " << buf << std::endl;
    } catch(std::exception&) {
        throw;
    }
}
    
void Verify::execute() {
    try {
        RopBind rop = NewRopBind();
        verify(rop);
    } catch(std::exception&) {
        throw;
    }
}

#ifndef CEROP_EX_TEST

int main(int argc, char **argv) {
    Verify *ver = new Verify();
    ver->execute();
    delete ver;
}

#endif // CEROP_EX_TEST

