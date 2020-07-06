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

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/dump.c

#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>
#include <exception>
#include "Dump.hpp"


// stdin reader
bool Dump::ReadCallBack(void *ctx, void *buf, size_t len, size_t *read) {
    size_t rd = std::fread(buf, 1, len, stdin);
    if(read != nullptr)
        *read = rd;
    return std::ferror(stdin) == 0;
}
void Dump::RCloseCallBack(void *ctx) {}
    
// stdout writer
bool Dump::WriteCallBack(void *ctx, const void *buf, size_t len) {
//    ssize_t wlen = write(STDOUT_FILENO, buf, len);
    size_t wlen = static_cast<size_t>(fwrite(buf, 1, len, stdout));
    return (wlen >= 0) && wlen == len;
}
void Dump::WCloseCallBack(void *ctx, bool discard) {
    std::cout << std::endl;
}
    
void Dump::print_usage(const std::string& program_name) {
    size_t pos = program_name.find_last_of("\\/");
    std::cout <<
        "Program dumps PGP packets. \n\nUsage:\n"
        "\t" << (pos!=std::string::npos? program_name.substr(pos+1) : program_name) <<
        " [-d|-h] [input.pgp]\n"
        "\t  -d : indicates whether to print packet content. Data is represented as hex\n"
        "\t  -m : dump mpi values\n"
        "\t  -g : dump key fingerprints and grips\n"
        "\t  -j : JSON output\n"
        "\t  -h : prints help and exists\n";
}

void Dump::execute(const int argc, const char*const* argv, std::string* json_out) {
    std::string input_file;
    bool raw = false;
    bool mpi = false;
    bool grip = false;
    bool json = false;
    bool help = (argc < 2);

    /* Parse command line options:
        -i input_file [mandatory]: specifies name of the file with PGP packets
        -d : indicates wether to dump whole packet content
        -m : dump mpi contents
        -g : dump key grips and fingerprints
        -j : JSON output
        -h : prints help and exists
    */
    std::vector<std::string> opts, args;
    std::string optList("dmgjh");
    for(int idx = 1; idx < argc; idx++)
        if(std::strlen(argv[idx]) >= 2 && argv[idx][0] == '-' && optList.find(argv[idx][1]) != std::string::npos)
            opts.push_back(argv[idx]);
        else
            args.push_back(argv[idx]);
    for(std::string opt : opts) {
        if(opt == "-d")
            raw = true;
        else if(opt == "-m")
            mpi = true;
        else if(opt == "-g")
            grip = true;
        else if(opt == "-j")
            json = true;
        else if(opt.length() > 0)
            help = true;
    }
    if(!help) {
        if(args.size() > 0)
            input_file = args[0];

        RopBind rop = NewRopBind();
        try {
            RopInput input;
            RopOutput output;
            try {
                if(input_file.length() > 0)
                    input = rop->create_input(input_file);
                else
                    input = rop->create_input(*this, nullptr);
            } catch(RopError& err) {
                std::cout << "Failed to open source: error " << std::hex << err.getErrCode() << std::dec << std::endl;
                throw;
            }

            if(!json) {
                try {
                    output = rop->create_output(*this, nullptr);
                } catch(RopError& err) {
                    std::cout << "Failed to open stdout: error " << std::hex << err.getErrCode() << std::dec << std::endl;
                    throw;
                }
                input->dump_packets_to_output(output, mpi, raw, grip);
            } else {
                RopData jsn = input->dump_packets_to_json(mpi, raw, grip);
                if(json_out == nullptr) {
                    std::cout << jsn << std::endl;
                } else
                    *json_out = *(String)*jsn;
            }
        } catch(RopError& err) {
            // Inform in case of error occured during parsing
            std::cout << "Operation failed [error code: " << std::hex << err.getErrCode() << std::dec << "]" << std::endl;
            throw;
        }
    } else {
        print_usage(argv[0]);
    }
}


#ifndef CEROP_EX_TEST

int main(int argc, char **argv) {
    Dump *dump = new Dump();
    dump->execute(argc, argv, nullptr);
    delete dump;
}

#endif // CEROP_EX_TEST
