// Copyright 2004-present Facebook. All Rights Reserved.

#include "JKeyChain.h"

using facebook::jni::local_ref;

namespace facebook { namespace conceal { namespace jni {

local_ref<jbyteArray> JKeyChain::getCipherKey() {
  static auto method = javaClassStatic()->getMethod<jbyteArray()>("getCipherKey");
  return facebook::jni::make_local(method(self()));
}

local_ref<jbyteArray> JKeyChain::getNewIV() {
  static auto method = javaClassStatic()->getMethod<jbyteArray()>("getNewIV");
  return facebook::jni::make_local(method(self()));
}

}}}
