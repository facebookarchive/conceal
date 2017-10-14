// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Buffer.h"
#include "MacConfig.h"
#include "Slice.h"
#include "WithState.h"
#include <openssl/hmac.h>

namespace facebook { namespace conceal {

class MacEncoder: private WithState {

 public:
  MacEncoder(MacConfig config, Slice key, Slice entity);
  MacEncoder(MacEncoder&& other) = default;
  virtual ~MacEncoder();

  /**
   * Initialize encoding and returns the result header.
   * This slice should be included in the output.
   * After calling start, you can call write.
   */
  Slice start();

  /**
   * Receives a new chunk of data to encode.
   */
  void write(Slice data);

  /**
   * Finishes encoding and return the ending tag that should be
   * included with the mac'ed output.
   * This tag allows the integrity-check on reading.
   */
  Slice end();

 private:
  MacConfig config_;
  Buffer buffer_;
  // slices over buffer
  Slice version_;
  Slice key_;
  Slice entity_;
  Buffer tag_;
  HMAC_CTX* ctx_;

  void update(Slice slice);
};

}}
