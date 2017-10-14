// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Buffer.h"
#include "CryptoConfig.h"
#include "Encrypt.h"
#include "Decrypt.h"
#include "KeyChain.h"
#include "Slice.h"

namespace facebook { namespace conceal {

class Cipher {
 public:
  Cipher(CryptoConfig config, KeyChain& keyChain);

  Encrypt createEncrypt(Slice entity);
  Decrypt createDecrypt(Slice entity);
 private:
  const CryptoConfig config_;
  KeyChain& keyChain_;
};

}}
