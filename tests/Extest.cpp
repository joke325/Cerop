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
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <exception>
#include <cerop.hpp>
#include "nano_json.hpp"

#include <Generate.hpp>
#include <Encrypt.hpp>
#include <Decrypt.hpp>
#include <Sign.hpp>
#include <Verify.hpp>
#include <Dump.hpp>


using namespace tech::janky::cerop;
using namespace tech::janky::utils;

class RopExamplesTest {
public:
    static void setUp();
    static void tearDown();

    void test_examples(int argc, char **argv);
    
protected:
    void right_cmp_json(JsonNode& json, JsonNode& ref_json);

    static std::vector<std::string> test_key_ids;
};


std::vector<std::string> RopExamplesTest::test_key_ids;

void RopExamplesTest::setUp() {
    for(std::string fname : {"pubring.pgp", "secring.pgp"}) {
        remove(fname.c_str());
    }
}
    
void RopExamplesTest::tearDown() {
    std::vector<std::string> fnames;
    for(std::string name : {"pubring.pgp", "secring.pgp", "encrypted.asc", "signed.asc"})
        fnames.push_back(name);
    for(std::string keyid : test_key_ids) {
        fnames.push_back(std::string("key-") + keyid + "-pub.asc");
        fnames.push_back(std::string("key-") + keyid + "-sec.asc");
    }
    for(std::string fname : fnames) {
        remove(fname.c_str());
    }
}

void RopExamplesTest::test_examples(int argc, char **argv) {
    //Execute
    { std::shared_ptr<Generate> generator(new Generate());
        generator->execute(); }
    { std::shared_ptr<Encrypt> encryptor(new Encrypt());
        encryptor->execute(); }
    { std::shared_ptr<Decrypt> decryptor(new Decrypt());
        decryptor->execute(); }
    if(!(Encrypt::message == Decrypt::message))
        throw std::runtime_error("Decryption Failed!");

    { std::shared_ptr<Sign> signer(new Sign());
        signer->execute(); }
    for(int idx = 0; idx < 2; idx++)
        test_key_ids.push_back(Sign::key_ids[idx]);

    { std::shared_ptr<Verify> verifier(new Verify());
        verifier->execute(); }
    std::string out;
    { std::shared_ptr<Dump> dumper(new Dump());
        const char* args[] = {"Dump", "-j", "signed.asc"};
        dumper->execute(3,  args, &out); }

    //Parse the dump
    JsonNode jso = ParseJson(out.c_str());

    std::string path(argv[0]);
    size_t pos = path.find_last_of("\\/");
    path = (pos!=std::string::npos? path.substr(0, pos+1) : std::string()) + "et_json.txt";
    std::ifstream file(path, std::ios_base::binary|std::ios_base::in);
    std::stringstream fdata;
    fdata << file.rdbuf();
    file.close();
    std::string data = fdata.str();

    std::vector<std::string> lcases;
    for(std::string str : {Sign::key_fprints[0], Sign::key_ids[0], Sign::key_fprints[1], Sign::key_ids[1]}) {
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
        lcases.push_back(str);
    }
    data = std::regex_replace(data, std::regex("b2617b172b2ceae2a1ed72435fc1286cf91da4d0"), lcases[0]);
    data = std::regex_replace(data, std::regex("5fc1286cf91da4d0"), lcases[1]);
    data = std::regex_replace(data, std::regex("f1768c67ec5a9ead3061c2befeee14c57b1a12d9"), lcases[2]);
    data = std::regex_replace(data, std::regex("feee14c57b1a12d9"), lcases[3]);
    JsonNode ref_jso = ParseJson(data.c_str());

    // Compare the jsons
    right_cmp_json(jso, ref_jso);
}
    
void RopExamplesTest::right_cmp_json(JsonNode& json, JsonNode& ref_json) {
    if(ref_json.arr)
        for(size_t idx = 0; idx < ref_json.arr->size(); idx++) 
            right_cmp_json((*json.arr)[idx], (*ref_json.arr)[idx]);
    else if(ref_json.obj) {
        if(ref_json.obj->size() > 0)
            for(JsonObject::value_type pair : *ref_json.obj) {
                right_cmp_json((*json.obj)[pair.first], pair.second);
            }
    } else if(!(json.str->s == ref_json.str->s))
        throw std::runtime_error("FAILED!");
}

int main(int argc, char **argv) {
    RopExamplesTest::setUp();
    RopExamplesTest *tex = new RopExamplesTest();
    tex->test_examples(argc, argv);
    delete tex;
    RopExamplesTest::tearDown();
    std::cout << std::endl << "SUCCESS !" << std::endl;
}
