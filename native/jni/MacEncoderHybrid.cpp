// Copyright 2004-present Facebook. All Rights Reserved.

#include "MacEncoderHybrid.h"
#include "JavaArrays.h"

using facebook::jni::alias_ref;
using facebook::jni::local_ref;

namespace facebook { namespace conceal { namespace jni {

local_ref<MacEncoderHybrid::jhybriddata> MacEncoderHybrid::initHybrid(
    alias_ref<jclass>,
    alias_ref<jbyteArray> key,
    alias_ref<jbyteArray> entity) {
  auto pinnedKey = key->pin();
  auto pinnedEntity = entity->pin();

  MacConfig config = MacConfig::get();

  // we only need the slices to build the object, and then they can be discarded
  auto result = makeCxxInstance(
      config,
      Slice(reinterpret_cast<uint8_t*>(&pinnedKey[0]), pinnedKey.size()),
      Slice(reinterpret_cast<uint8_t*>(&pinnedEntity[0]), pinnedEntity.size()));

  pinnedEntity.abort();
  pinnedKey.abort();

  return result;
}

void MacEncoderHybrid::registerNatives() {
  registerHybrid({
    makeNativeMethod("initHybrid", MacEncoderHybrid::initHybrid),
    makeNativeMethod("start", MacEncoderHybrid::start),
    makeNativeMethod("write", "([BII)V", MacEncoderHybrid::write),
    makeNativeMethod("end", MacEncoderHybrid::end),
  });
}

// Thing is a hybrid class declared elsewhere.
local_ref<jbyteArray> MacEncoderHybrid::start() {
  Slice header = encoder_.start();
  return slice2JavaArray(header);
}

void MacEncoderHybrid::write(alias_ref<jbyteArray> data, jint offset, jint count) {
  auto pinnedData = data->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedData[0]), pinnedData.size());
  // Slice API will check the boundaries
  encoder_.write(slice(offset, offset + count));
  pinnedData.abort();
}

local_ref<jbyteArray> MacEncoderHybrid::end() {
  Slice tail = encoder_.end();
  return slice2JavaArray(tail);
}

MacEncoderHybrid::MacEncoderHybrid(MacConfig config, Slice key, Slice entity)
  : encoder_(config, key, entity) {}

}}}
