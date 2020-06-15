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

#include <cstring>
#include <iostream>
#include <exception>
#include "Decrypt.hpp"


std::string Decrypt::message = "Dummy";

SessionPassCallBack::Ret Decrypt::PassCallBack(const RopSession& ses, void* ctx, const RopKey& key, const InString& pgpCtx, const size_t bufLen) {
    if(strcmp(pgpCtx, "decrypt (symmetric)") == 0)
        return SessionPassCallBack::Ret(true, "encpassword");
    if(strcmp(pgpCtx, "decrypt") == 0)
        return SessionPassCallBack::Ret(true, "password");
    return SessionPassCallBack::Ret(false, nullptr);
}

void Decrypt::decrypt(RopBind& rop, const bool usekeys) {
    try {
        // initialize FFI object
        RopSession ses = rop->create_session(RopBindT::KEYSTORE_GPG, RopBindT::KEYSTORE_GPG);

        // check whether we want to use key or password for decryption
        if(usekeys) {
            try {
                // load secret keyring, as it is required for public-key decryption. However, you may
                // need to load public keyring as well to validate key's signatures.
                RopInput keyfile = rop->create_input("secring.pgp");
                // we may use secret=True and public=True as well
                ses->load_keys_secret(RopBindT::KEYSTORE_GPG, keyfile);
            } catch(RopError&) {
                std::cout << "Failed to read secring" << std::endl;
                throw;
            }
        }

        // set the password provider
        ses->set_pass_provider(this, nullptr);
        std::string buf;
        try {
            // create file input and memory output objects for the encrypted message and decrypted
            // message
            RopInput input = rop->create_input("encrypted.asc");
            RopOutput output = rop->create_output(0);
            ses->decrypt(input, output);
            // get the decrypted message from the output structure
            buf = *(String)*output->memory_get_buf(false);
        } catch(RopError&) {
            std::cout << "Public-key decryption failed";
            throw;
        }

        std::cout << "Decrypted message (" << (usekeys? "with key" : "with password") << "):" << std::endl;
        std::cout << buf << std::endl;
        Decrypt::message = buf;
    } catch(std::exception&) {
        throw;
    }
}
    
void Decrypt::execute() {
    try {
        RopBind rop = NewRopBind();
        decrypt(rop, true);
        decrypt(rop, false);
    } catch(std::exception&) {
        throw;
    }
}

#ifndef CEROP_EX_TEST

int main(int argc, char **argv) {
    Decrypt *dec = new Decrypt();
    dec->execute();
    delete dec;
}

#endif // CEROP_EX_TEST
