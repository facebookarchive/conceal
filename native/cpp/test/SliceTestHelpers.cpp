// Copyright 2004-present Facebook. All Rights Reserved.

#include "SliceTestHelpers.h"

// Helper functions for tests

namespace facebook { namespace conceal {

void fillRange(Slice slice) {
  for (size_t i=0; i<slice.length(); i++) {
    slice[i] = i;
  }
}

uint8_t hex2int(char val) {
  if (val >= '0' && val <= '9') {
    return val - '0';
  } else if (val >= 'a' && val <= 'f') {
    return val - 'a' + 10;
  } else if (val >= 'A' && val <= 'F') {
    return val - 'A' + 10;
  } else {
    return -1;
  }
}

Buffer hex2Buffer(const char* hex) {
  size_t length = strlen(hex) / 2;
  Buffer result(length);
  for (size_t i=0; i<length; i++) {
    uint8_t value = hex2int(*(hex++)) << 4;
    value |= hex2int(*(hex++));
    result[i] = value;
  }
  return result;
}

}}
