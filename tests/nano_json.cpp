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

#include <string.h>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include "nano_json.hpp"


namespace tech {
    namespace janky {
        namespace utils {

static std::string Shorten(const char* text, unsigned maxLen = 30) {
    return std::string(text, std::min<size_t>(maxLen, strlen(text)));
}

static JsonNode ParseValue(const char** text) {
    JsonNode val;
    JsonValue str;
    int step = 0;
    bool esc = false;
    while(char ch = **text) {
        (*text)++;
        if(ch == '\\') {
            esc = true;
            continue;
        }
        if(esc) {
            switch(ch) {
            case 'b': ch = '\b'; break;
            case 'f': ch = '\f'; break;
            case 'n': ch = '\n'; break;
            case 'r': ch = '\r'; break;
            case 't': ch = '\t'; break;
            }
            esc = false;
        }
        if(ch > ' ') {
            switch(step) {
            case 0:
                switch(ch) {
                case '{':
                {
                    val.obj.reset(new JsonObject());
                    JsonNode ret = ParseValue(text);
                    if(!ret || ret.str)
                        str = (ret.str? *ret.str : JsonValue());
                    else
                        throw std::runtime_error(std::string("Unexpected value"));
                }
                    step = 11;
                    break;
                case '[':
                    val.arr.reset(new JsonArray());
                    val.arr->push_back(ParseValue(text));
                    step = 21;
                    break;
                case '\"':
                    str.t = JsonValue::JTString;
                    step = 1;
                    break;
                case '\'':
                    str.t = JsonValue::JTString2;
                    step = 2;
                    break;
                default:
                    if(strchr(",:]}", ch)) {
                        (*text)--;
                        if(str.s.length() > 0)
                            val.str.reset(new JsonValue(str));
                        return val;
                    }
                    str.s.push_back(ch);
                    step = 3;
                }
                continue;
            case 3:
                if(strchr(",:[]{}\'\"", ch)) {
                    (*text)--;
                    if(str.s.length() > 0)
                        val.str.reset(new JsonValue(str));
                    return val;
                }
                break;
            case 11:
                if(ch == ':') {
                    val.obj->insert(JsonObject::value_type(str, ParseValue(text)));
                    step++;
                } else if(ch == '}') {
                    return val;
                } else
                    throw std::runtime_error(std::string("Unexpected character: ") + Shorten(*text-1));
                break;
            case 12:
                if(ch == '}') {
                    return val;
                } else if(ch == ',') {
                    JsonNode ret = ParseValue(text);
                    if(!ret || ret.str)
                        str = (ret.str? *ret.str : JsonValue());
                    else
                        throw std::runtime_error(std::string("Unexpected value"));
                    step--;
                } else
                    throw std::runtime_error(std::string("Unexpected character: ") + Shorten(*text-1));
                break;
            case 21:
                if(ch == ',') {
                    val.arr->push_back(ParseValue(text));
                } else if(ch == ']') {
                    return val;
                } else
                    throw std::runtime_error(std::string("Unexpected character: ") + Shorten(*text-1));
                break;
            }
        }

        switch(step) {
        case 1:
        case 2:
        case 3:
            if((step == 1 && ch == '\"') || (step == 2 && ch == '\'') || (step == 3 && !(ch > ' '))) {
                val.str.reset(new JsonValue(str));
                return val;
            }
            str.s.push_back(ch);
            break;
        }
    }
    return val;
}

JsonNode ParseJson(const char* text) {
    const char *txt = text, *txtEnd;
    JsonNode json = ParseValue(&txt);
    txtEnd = txt;
    if(ParseValue(&txt))
        throw std::invalid_argument(std::string("Unexpected end: ") + Shorten(txtEnd));
    return json;
}

std::ostream& EscStr(std::ostream& out, const JsonValue& str) {
    std::string quot = "";
    switch(str.t) {
    case JsonValue::JTString: quot = "\""; break;
    case JsonValue::JTString2: quot = "\'"; break;
    default: ;
    }
    out << quot;
    for(char ch : str.s) {
        switch(ch) {
            case '\"': out << "\\\""; break;
            case '/': out << "\\/"; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << ch;
        }
    }
    out << quot;
    return out;
}

std::ostream& DumpJson(std::ostream& out, const JsonNode& json, const int indSize, const int indent) {
    std::string offL(indSize*indent, ' '), offR(indSize*(indent+1), ' ');
    if(json.str) {
        EscStr(out, *json.str);
    } else if(json.obj) {
        out << "{";
        if(indSize)
            out << std::endl;
        size_t item = 0, count = json.obj->size();
        for(auto pr : *json.obj) {
            EscStr(out << offR, pr.first) << (indSize? " : " : ":");
            DumpJson(out, pr.second, indSize, indent+1);
            out << (++item<count? "," : "");
            if(indSize)
                out << std::endl;
        }
        out << offL << "}";
    } else if(json.arr) {
        out << "[";
        if(indSize)
            out << std::endl;
        size_t item = 0, count = json.arr->size();
        for(JsonNode vl : *json.arr) {
            out << offR;
            DumpJson(out, vl, indSize, indent+1);
            out << (++item<count? "," : "");
            if(indSize)
                out << std::endl;
        }
        out << offL << "]";
    }
    return out;
}

JsonNode* JsonNode::operator[](const std::string& key) const {
    if(obj) {
        JsonObject::iterator it = obj->find(key);
        if(it != obj->end())
            return &it->second;
    }
    return nullptr;
}

JsonNode JsonNode::getDefault(const std::string& key, const char* deflt) const {
    if(obj) {
        JsonObject::iterator it = obj->find(key);
        if(it != obj->end())
            return it->second;
    }
    JsonNode ret;
    if(deflt != nullptr)
        ret.str.reset(new JsonValue(deflt));
    return ret;
}

JsonNode* JsonNode::operator[](const size_t index) const {
    if(arr && index < arr->size())
        return &arr->at(index);
    return nullptr;
}

} } }
