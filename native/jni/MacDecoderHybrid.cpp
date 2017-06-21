// Copyright 2004-present Facebook. All Rights Reserved.

#include "MacDecoderHybrid.h"
#include "JavaArrays.h"

namespace facebook { namespace conceal { namespace jni {

local_ref<MacDecoderHybrid::jhybriddata> MacDecoderHybrid::initHybrid(
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

void MacDecoderHybrid::registerNatives() {
  registerHybrid({
    makeNativeMethod("initHybrid", MacDecoderHybrid::initHybrid),
    makeNativeMethod("start", MacDecoderHybrid::start),
    makeNativeMethod("read", MacDecoderHybrid::read),
    makeNativeMethod("end", MacDecoderHybrid::end),
  });
}

// Thing is a hybrid class declared elsewhere.
void MacDecoderHybrid::start(alias_ref<jbyteArray> header) {
  auto pinnedHeader = header->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedHeader[0]), pinnedHeader.size());
  decoder_.start(slice);
  pinnedHeader.abort();
}

void MacDecoderHybrid::read(alias_ref<jbyteArray> data, jint offset, jint count) {
  auto pinnedData = data->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedData[0]), pinnedData.size());
  // Slice API will check the boundaries
  decoder_.read(slice(offset, offset + count));
  pinnedData.abort();
}

bool MacDecoderHybrid::end(alias_ref<jbyteArray> tail) {
  auto pinnedTail = tail->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedTail[0]), pinnedTail.size());
  bool result = decoder_.end(slice);
  pinnedTail.abort();
  return result;
}

MacDecoderHybrid::MacDecoderHybrid(MacConfig config, Slice key, Slice entity)
  : decoder_(config, key, entity) {}

}}}
