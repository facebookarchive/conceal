// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <conceal/Slice.h>
#include <fb/fbjni.h>

using facebook::jni::local_ref;

namespace facebook { namespace conceal { namespace jni {

local_ref<jbyteArray> slice2JavaArray(ConstSlice slice);

}}}
