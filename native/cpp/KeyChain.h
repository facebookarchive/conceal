// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Buffer.h"
#include "Slice.h"

namespace facebook { namespace conceal {

/**
 * Returns the key and the IVs a Crypto object would use.
 * Key: same can be returned many times. Therefore a Slice
 *      must be returned, and the ownership is KeyChain's.
 * IV: a new one is generated on each call so a Buffer is
 *     returned (in fact, that ensures it's not used again).
 * Both Encrypt and Decrypt objects create their own copies
 * so they are independent.
 * **************************************
 * Implementations must be thread-safe!
 * **************************************
 */
class KeyChain {
 public:
  virtual const Slice getKey()=0;
  virtual Buffer createIv()=0;
 protected:
  KeyChain() {};
};

}}
