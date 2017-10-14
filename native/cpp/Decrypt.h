// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Buffer.h"
#include "CryptoConfig.h"
#include "Slice.h"
#include "WithState.h"
#include <openssl/evp.h>

namespace facebook { namespace conceal {

class Decrypt: private WithState {

   public:
    Decrypt(CryptoConfig config, Slice key, Slice entity);
    Decrypt(Decrypt&& other);
    virtual ~Decrypt();

    void start(Slice header);
    void read(Slice src, Slice target);
    bool end(Slice tail);


  private:
    CryptoConfig config_;
    Buffer buffer_;
    // slices over buffer
    Slice version_;
    Slice iv_;
    Slice key_;
    Buffer entity_;
    EVP_CIPHER_CTX* ctx_;

    int updateAad(Slice slice);
};

}}
