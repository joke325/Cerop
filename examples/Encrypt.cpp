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

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/encrypt.c

#include <iostream>
#include <exception>
#include "Encrypt.hpp"


const std::string Encrypt::message = "ROP encryption sample message";

void Encrypt::encrypt(RopBind& rop) {
    try {
        // initialize
        RopSession ses = rop->create_session(RopBindT::KEYSTORE_GPG, RopBindT::KEYSTORE_GPG);

        try {
            // load public keyring - we do not need secret for encryption
            RopInput keyfile = rop->create_input("pubring.pgp");
            // we may use secret=True and public=True as well
            ses->load_keys_public(RopBindT::KEYSTORE_GPG, keyfile);
        } catch(RopError&) {
            std::cout << "Failed to read pubring" << std::endl;
            throw;
        }

        try {
            // create memory input and file output objects for the message and encrypted message
            RopInput input = rop->create_input(message, false);
            RopOutput output = rop->create_output("encrypted.asc");
            // create encryption operation
            RopOpEncrypt encrpt = ses->op_encrypt_create(input, output);

            // setup encryption parameters
            encrpt->set_armor(true);
            encrpt->set_file_name("message.txt");
            encrpt->set_file_mtime(std::chrono::time_point_cast<Duration>(Instant::clock::now()));
            encrpt->set_compression("ZIP", 6);
            encrpt->set_cipher(RopBindT::ALG_SYMM_AES_256);
            encrpt->set_aead("None");

            // locate recipient's key and add it to the operation context. While we search by userid
            // (which is easier), you can search by keyid, fingerprint or grip.
            RopKey key = ses->locate_key("userid", "rsa@key");
            encrpt->add_recipient(key);
            // add encryption password as well
            encrpt->add_password("encpassword", RopBindT::ALG_HASH_SHA256, 0, RopBindT::ALG_SYMM_AES_256);

            // execute encryption operation
            encrpt->execute();

            std::cout << "Encryption succeded. Encrypted message written to file encrypted.asc" << std::endl;
        } catch(RopError&) {
            std::cout << "Encryption failed" << std::endl;
            throw;
        }
    } catch(std::exception&) {
        throw;
    }
}

void Encrypt::execute() {
    try {
        RopBind rop = NewRopBind();
        encrypt(rop);
    } catch(std::exception&) {
        throw;
    }
}

#ifndef CEROP_EX_TEST

int main(int argc, char **argv) {
    Encrypt *enc = new Encrypt();
    enc->execute();
    delete enc;
}

#endif // CEROP_EX_TEST
