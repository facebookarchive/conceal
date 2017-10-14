// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Buffer.h"
#include "CryptoConfig.h"
#include "Slice.h"
#include "WithState.h"
#include <openssl/evp.h>

namespace facebook { namespace conceal {

class Encrypt: private WithState {

  public:
    Encrypt(CryptoConfig config, Slice key, Slice iv, Slice entity);
    Encrypt(Encrypt&& other);
    virtual ~Encrypt();

    /**
     * Initialize encryption and returns the encrypted result header.
     * This slice should be included in the encrypted output.
     * After calling start, you can call write.
     */
    Slice start();

    /**
     * Receives a new chunk of data to encrypt.
     * Target will be the corresponding cipher text.
     * Target length should be at least the same as src's.
     * Exactly the same amount of bytes are written.
     */
    void write(Slice src, Slice target);

    /**
     * Finishes encryption and return the ending tag that should be
     * included with the cipher. This tag allows an integrity-check
     * later on decryption.
     */
    Slice end();


  private:
    CryptoConfig config_;
    Buffer buffer_;
    // slices over buffer
    Slice version_;
    Slice iv_;
    Slice key_;
    Buffer entity_;
    Buffer tag_;
    EVP_CIPHER_CTX* ctx_;

    int updateAad(Slice slice);
};

}}
