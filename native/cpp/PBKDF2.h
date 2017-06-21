// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <memory>
#include "Buffer.h"
#include "Slice.h"
#include <openssl/evp.h>

namespace facebook { namespace conceal {

class PBKDF2 {

 public:
  PBKDF2();

  // configuration
  void setIterations(int iterations);
  void setPassword(ConstSlice password);
  /**
   * Currently you need to set the salt.
   * Later it will be generated randomly if null.
   */
  void setSalt(ConstSlice salt);
  void setKeyLengthInBytes(int keyLength);

  // use
  ConstSlice generate();

  // subsequent getters
  ConstSlice getSalt();
  ConstSlice getKey();

 private:
   int iterations_;
   std::unique_ptr<Buffer> password_;
   std::unique_ptr<Buffer> salt_;
   int keyLengthInBytes_;
   std::unique_ptr<Buffer> generatedKey_;
};

}}
