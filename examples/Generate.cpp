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

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/generate.c

#include <cstring>
#include <iostream>
#include <exception>
#include "Generate.hpp"


const std::string Generate::RSA_KEY_DESC = 
        "{"
            "'primary': {"
                "'type': 'RSA',"
                "'length': 2048,"
                "'userid': 'rsa@key',"
                "'expiration': 31536000,"
                "'usage': ['sign'],"
                "'protection': {"
                    "'cipher': 'AES256',"
                    "'hash': 'SHA256'"
                "}"
            "},"
            "'sub': {"
                "'type': 'RSA',"
                "'length': 2048,"
                "'expiration': 15768000,"
                "'usage': ['encrypt'],"
                "'protection': {"
                    "'cipher': 'AES256',"
                    "'hash': 'SHA256'"
                "}"
            "}"
        "}";
const std::string Generate::CURVE_25519_KEY_DESC = 
        "{"
            "'primary': {"
                "'type': 'EDDSA',"
                "'userid': '25519@key',"
                "'expiration': 0,"
                "'usage': ['sign'],"
                "'protection': {"
                    "'cipher': 'AES256',"
                    "'hash': 'SHA256'"
                "}"
            "},"
            "'sub': {"
                "'type': 'ECDH',"
                "'curve': 'Curve25519',"
                "'expiration': 15768000,"
                "'usage': ['encrypt'],"
                "'protection': {"
                    "'cipher': 'AES256',"
                    "'hash': 'SHA256'"
                "}"
            "}"
        "}";

/**
 * basic pass provider implementation, which always return 'password' for key protection.
 * You may ask for password via stdin, or choose password based on key properties, whatever else 
 */
SessionPassCallBack::Ret Generate::PassCallBack(const RopSession& ses, void* ctx, const RopKey& key, const InString& pgpCtx, const size_t bufLen) {
    if(strcmp(pgpCtx, "protect") == 0)
        return SessionPassCallBack::Ret(true, "password");
    return SessionPassCallBack::Ret(false, nullptr);
}

/**
 * This simple helper function just prints armored key, searched by userid, to stdout.
 */
void Generate::print_key(RopBind& rop, RopSession& ses, const std::string& uid, const bool secret) const {
    try {
        // you may search for the key via userid, keyid, fingerprint, grip
        RopKey key = ses->locate_key("userid", uid);
        // create in-memory output structure to later use buffer
        RopOutput keydata = rop->create_output(0);
        if(secret)
            key->export_secret(keydata, true, true);
        else
            key->export_public(keydata, true, true);
        // get key's contents from the output structure
        RopData buf = keydata->memory_get_buf(false);
        std::cout << buf << std::endl;
    } catch(std::exception&) {
        throw;
    }
}

void Generate::export_key(RopBind& rop, RopSession& ses, const std::string& uid, const bool secret) const {
    try {
        // you may search for the key via userid, keyid, fingerprint, grip
        RopKey key = ses->locate_key("userid", uid);
        // get key's id and build filename
        std::string filename(std::string("key-") + *(String)*key->keyid() + "-" + (secret? "sec" : "pub") + ".asc");
        RopOutput keyfile = rop->create_output(filename);
        key->export_key(keyfile, !secret, secret, true, true);
    } catch(std::exception&) {
        throw;
    }
}

void Generate::generate_keys(RopBind& rop) {
    RopSession ses = rop->create_session(RopBindT::KEYSTORE_GPG, RopBindT::KEYSTORE_GPG);
    try {
        // initialize
        RopSession ses = rop->create_session(RopBindT::KEYSTORE_GPG, RopBindT::KEYSTORE_GPG);
        try {
            // set password provider
            ses->set_pass_provider(this, nullptr);
            // generate EDDSA/X25519 keypair
            RopData key_grips = ses->generate_key_json(Generate::CURVE_25519_KEY_DESC);
            // generate RSA keypair
            key_grips = ses->generate_key_json(Generate::RSA_KEY_DESC);
            std::cout << "Generated RSA key/subkey:" << std::endl << key_grips << std::endl;
        } catch(RopError&) {
            std::cout << "Failed to generate keys" << std::endl;
            throw;
        }

        try {
            // create file output object and save public keyring with generated keys, overwriting
            // previous file if any. You may use max_alloc here as well.
            RopOutput keyfile = rop->create_output("pubring.pgp");
            ses->save_keys_public(RopBindT::KEYSTORE_GPG, keyfile);
        } catch(RopError&) {
            std::cout << "Failed to save pubring" << std::endl;
            throw;
        }

        try {
            // create file output object and save secret keyring with generated keys
            RopOutput keyfile = rop->create_output("secring.pgp");
            ses->save_keys_secret(RopBindT::KEYSTORE_GPG, keyfile);
        } catch(RopError&) {
            std::cout << "Failed to save secring" << std::endl;
            throw;
        }
    } catch(std::exception&) {
        throw;
    }
}

void Generate::output_keys(RopBind& rop) const {
    try {
        // initialize
        RopSession ses = rop->create_session(RopBindT::KEYSTORE_GPG, RopBindT::KEYSTORE_GPG);

        try {
            // load keyrings
            RopInput keyfile = rop->create_input("pubring.pgp");
            // actually, we may exclude the public  to not check key types
            ses->load_keys_public(RopBindT::KEYSTORE_GPG, keyfile);
        } catch(RopError&) {
            std::cout << "Failed to read pubring" << std::endl;
            throw;
        }

        try {
            RopInput keyfile = rop->create_input("secring.pgp");
            ses->load_keys_secret(RopBindT::KEYSTORE_GPG, keyfile);
        } catch(RopError&) {
            std::cout << "Failed to read secring" << std::endl;
            throw;
        }

        try {
            // print armored keys to the stdout
            print_key(rop, ses, "rsa@key", false);
            print_key(rop, ses, "rsa@key", true);
            print_key(rop, ses, "25519@key", false);
            print_key(rop, ses, "25519@key", true);
        } catch(std::exception&) {
            std::cout << "Failed to print armored key(s)" << std::endl;
            throw;
        }

        try {
            // write armored keys to the files, named key-<keyid>-pub.asc/named key-<keyid>-sec.asc
            export_key(rop, ses, "rsa@key", false);
            export_key(rop, ses, "rsa@key", true);
            export_key(rop, ses, "25519@key", false);
            export_key(rop, ses, "25519@key", true);
        } catch(std::exception&) {
            std::cout << "Failed to write armored key(s) to file" << std::endl;
            throw;
        }
    } catch(std::exception&) {
        throw;
    }
}

void Generate::execute() {
    try {
        RopBind rop = NewRopBind();
        generate_keys(rop);
        output_keys(rop);
    } catch(std::exception&) {
        throw;
    }
}

#ifndef CEROP_EX_TEST

int main(int argc, char **argv) {
    Generate *gen = new Generate();
    gen->execute();
    delete gen;
}

#endif // CEROP_EX_TEST
