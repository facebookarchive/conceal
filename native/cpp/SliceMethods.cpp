// Copyright 2004-present Facebook. All Rights Reserved.

#include "SliceMethods.h"

namespace facebook { namespace conceal {

/**
 * This is a compare between two equally-long slices that always compare
 * all the bytes. This avoids introducing a vulnerability that tells a
 * listening attacker how many bytes are equal and therefore allowing an
 * iterative-attack. The slices must be equal in length.
 */
bool SliceMethods::equalsConstantTime(Slice slice1, Slice slice2) {
  uint8_t result = 0;
  for (int i = 0, count = slice1.length(); i < count; i++) {
    result |= slice1[i] ^ slice2[i];
  }
  return result == 0;
}

}}
