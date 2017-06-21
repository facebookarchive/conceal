// Copyright 2004-present Facebook. All Rights Reserved.

#include <conceal/KeyChain.h>
#include <conceal/Slice.h>
#include <conceal/Buffer.h>

namespace facebook { namespace conceal {

/**
 * Implementation of KeyChain with a fixed key and IV.
 * For obvious reasons(*) it's only suitable for tests.
 *
 * (*) Hint: each IV should be used only once. Ever.
 */
class TestKeyChain: public KeyChain {
 public:
  TestKeyChain(Slice key, Slice iv)
    : KeyChain(),
      key_(key.length()),
      iv_(iv.length()) {
    key.copyTo(key_);
    iv.copyTo(iv_);
  }

  const Slice getKey() {
    return key_;
  }

  Buffer createIv() {
    Buffer result(iv_.length());
    iv_.copyTo(result);
    return result;
  }

 private:
  Buffer key_;
  Buffer iv_;
};

}}
