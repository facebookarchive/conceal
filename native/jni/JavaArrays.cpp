// Copyright 2004-present Facebook. All Rights Reserved.

#include "JavaArrays.h"

using facebook::jni::make_byte_array;

namespace facebook { namespace conceal { namespace jni {

local_ref<jbyteArray> slice2JavaArray(ConstSlice slice) {
  auto jArray = make_byte_array(slice.length());
  jArray->setRegion(
      0,
      slice.length(),
      reinterpret_cast<const jbyte*>(slice.offset(0)));
  return jArray;
}

}}}
