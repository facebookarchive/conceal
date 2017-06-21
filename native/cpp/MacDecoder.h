// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Buffer.h"
#include "MacConfig.h"
#include "Slice.h"
#include "WithState.h"
#include <openssl/hmac.h>

namespace facebook { namespace conceal {

class MacDecoder: private WithState {

 public:
  MacDecoder(MacConfig config, Slice key, Slice entity);
  MacDecoder(MacDecoder&& other) = default;
  virtual ~MacDecoder();

  void start(Slice header);
  void read(Slice src);
  bool end(Slice tail);


 private:
  MacConfig config_;
  Buffer buffer_;
  // slices over buffer
  Slice version_;
  Slice key_;
  Slice entity_;
  HMAC_CTX* ctx_;

  void update(Slice slice);
  bool equalsConstantTime(Slice slice1, Slice slice2);
};

}}
