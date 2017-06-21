// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Slice.h"

namespace facebook { namespace conceal {

class SliceMethods {
 public:

  /**
  * This is a compare between two equally-long slices that always compare
  * all the bytes. This avoids introducing a vulnerability that tells a
  * listening attacker how many bytes are equal and therefore allowing an
  * iterative-attack. The slices must be equal in length.
  */
  static bool equalsConstantTime(Slice slice1, Slice slice2);

 private:
  SliceMethods() = delete;
};

}}
