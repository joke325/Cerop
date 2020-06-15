# Copyright (c) 2020 Janky <box@janky.tech>
# All right reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#

add_executable(generate Generate.cpp)
target_include_directories(generate PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(generate cerop ${CMAKE_DL_LIBS})

add_executable(encrypt Encrypt.cpp)
target_include_directories(encrypt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(encrypt cerop ${CMAKE_DL_LIBS})

add_executable(decrypt Decrypt.cpp)
target_include_directories(decrypt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(decrypt cerop ${CMAKE_DL_LIBS})

add_executable(sign Sign.cpp)
target_include_directories(sign PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(sign cerop ${CMAKE_DL_LIBS})

add_executable(verify Verify.cpp)
target_include_directories(verify PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(verify cerop ${CMAKE_DL_LIBS})

add_executable(dump Dump.cpp)
target_include_directories(dump PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(dump cerop ${CMAKE_DL_LIBS})
