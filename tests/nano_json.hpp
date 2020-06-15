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

#ifndef NANO_JSON_H
#define NANO_JSON_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <stdexcept>


namespace tech {
    namespace janky {
        namespace utils {

struct JsonValue {
    enum Type { JTUndef, JTString, JTString2 };
    inline JsonValue() : t(JTUndef) {}
    inline JsonValue(const char* str) : s(str), t(JTString) {}
    inline JsonValue(const std::string& str) : s(str), t(JTString) {}
    inline operator long() const { return std::stol(s); }
    inline operator double() const { return std::stod(s); }
    inline operator bool() const { 
        std::string lwr(s);
        std::transform(lwr.begin(), lwr.end(), lwr.begin(), ::tolower);
        if(lwr == "true")
            return true;
        if(lwr == "false")
            return false;
        throw std::invalid_argument(s);
    }
    inline bool isNull() const { 
        std::string lwr(s);
        std::transform(lwr.begin(), lwr.end(), lwr.begin(), ::tolower);
        return lwr == "null";
    }
    inline bool operator <(const JsonValue& j2) const { return s < j2.s; }
    std::string s;
    Type t;
};

struct JsonNode {
    std::shared_ptr<JsonValue> str;
    std::shared_ptr<std::map<JsonValue, JsonNode> > obj;
    std::shared_ptr<std::vector<JsonNode> > arr;

    JsonNode* operator[](const std::string& key) const;
    inline JsonNode* operator[](const char* key) const { return this->operator[](std::string(key)); }
    JsonNode getDefault(const std::string& key, const char* deflt = nullptr) const;
    JsonNode* operator[](const size_t index) const;
    inline operator const char*() const { return str? str->s.c_str() : nullptr; }
    inline operator bool() const { return str || obj || arr; }
    inline bool isObject() const { return (bool)obj; }
    inline bool isArray() const { return (bool)arr; }
    inline bool isValue() const { return (bool)str; }
};

typedef std::map<JsonValue, JsonNode> JsonObject;
typedef std::vector<JsonNode> JsonArray;

JsonNode ParseJson(const char* text);
std::ostream& DumpJson(std::ostream& out, const JsonNode& json, const int indSize = 3, const int indent = 0);

} } }

#endif // NANO_JSON_H
