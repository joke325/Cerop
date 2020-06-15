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
#include "Sign.hpp"


std::string Sign::key_ids[2] = {"Dummy", "Dummy"};
std::string Sign::key_fprints[2] = {"Dummy", "Dummy"};

// an example pass provider
SessionPassCallBack::Ret Sign::PassCallBack(const RopSession& ses, void* ctx, const RopKey& key, const InString& pgpCtx, const size_t bufLen) {
    return SessionPassCallBack::Ret(true, "password");
}

void Sign::sign(RopBind& rop) {
    std::string message = "ROP signing sample message";

    try {
        // initialize
        RopSession ses = rop->create_session(RopBindT::KEYSTORE_GPG, RopBindT::KEYSTORE_GPG);

        std::string err_desc;
        try {
            // load secret keyring, as it is required for signing. However, you may need
            // to load public keyring as well to validate key's signatures.
            err_desc = "Failed to open secring.pgp. Did you run Generate.java sample?";
            RopInput keyfile = rop->create_input("secring.pgp");

            // we may use public=True and secret=True as well
            err_desc = "Failed to read secring.pgp";
            ses->load_keys_secret(RopBindT::KEYSTORE_GPG, keyfile);
        } catch(RopError&) {
            std::cout << err_desc << std::endl;
            throw;
        }

        // set the password provider - we'll need password to unlock secret keys
        ses->set_pass_provider(this, nullptr);

        // create file input and memory output objects for the encrypted message
        // and decrypted message
        RopOpSign sign;
        try {
            err_desc = "Failed to create input object";
            RopInput input = rop->create_input(message, false);

            err_desc = "Failed to create output object";
            RopOutput output = rop->create_output("signed.asc");

            // initialize and configure sign operation, use op_sign_create(cleartext/detached)
            // for cleartext or detached signature
            err_desc = "Failed to create sign operation";
            sign = ses->op_sign_create(input, output);
        } catch(RopError&) {
            std::cout << err_desc << std::endl;
            throw;
        }

        // armor, file name, compression
        sign->set_armor(true);
        sign->set_file_name("message.txt");
        sign->set_file_mtime(std::chrono::time_point_cast<Duration>(Instant::clock::now()));
        sign->set_compression("ZIP", 6);
        // signatures creation time - by default will be set to the current time as well
        sign->set_creation_time(std::chrono::time_point_cast<Duration>(Instant::clock::now()));
        // signatures expiration time - by default will be 0, i.e. never expire
        sign->set_expiration(std::chrono::hours(365*24));
        // set hash algorithm - should be compatible for all signatures
        sign->set_hash(RopBindT::ALG_HASH_SHA256);

        try {
            // now add signatures. First locate the signing key, then add and setup signature
            // RSA signature
            err_desc = "Failed to locate signing key rsa@key.";
            RopKey key = ses->locate_key("userid", "rsa@key");
            Sign::key_ids[0] = *key->keyid();
            Sign::key_fprints[0] = *key->fprint();

            err_desc = "Failed to add signature for key rsa@key.";
            sign->add_signature(key);

            // EdDSA signature
            err_desc = "Failed to locate signing key 25519@key.";
            key = ses->locate_key("userid", "25519@key");
            Sign::key_ids[1] = *(String)*key->keyid();
            Sign::key_fprints[1] = *(String)*key->fprint();

            err_desc = "Failed to add signature for key 25519@key.";
            sign->add_signature(key);

            // finally do signing
            err_desc = "Failed to add signature for key 25519@key.";
            sign->execute();

            std::cout << "Signing succeeded. See file signed.asc." << std::endl;
        } catch(RopError&) {
            std::cout << err_desc << std::endl;
            throw;
        }
    } catch(std::exception&) {
        throw;
    }
}

void Sign::execute() {
    try {
        RopBind rop = NewRopBind();
        sign(rop);
    } catch(std::exception&) {
        throw;
    }
}

#ifndef CEROP_EX_TEST

int main(int argc, char **argv) {
    Sign *sign = new Sign();
    sign->execute();
    delete sign;
}

#endif // CEROP_EX_TEST
