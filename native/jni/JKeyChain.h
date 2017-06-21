// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <fb/fbjni/CoreClasses.h>

namespace facebook { namespace conceal { namespace jni {

/**
 * Represents a Java KeyChain interface implementation.
 * This is the standard definition for types we need to invoke from native.
 */
struct JKeyChain : public facebook::jni::JavaClass<JKeyChain> {
  constexpr static auto kJavaDescriptor = "Lcom/facebook/crypto/keychain/KeyChain;";


  facebook::jni::local_ref<jbyteArray> getCipherKey();
  facebook::jni::local_ref<jbyteArray> getNewIV();
};

}}}
