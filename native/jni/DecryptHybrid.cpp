// Copyright 2004-present Facebook. All Rights Reserved.

#include "DecryptHybrid.h"

namespace facebook { namespace conceal { namespace jni {

local_ref<DecryptHybrid::jhybriddata> DecryptHybrid::initHybrid(
    alias_ref<jclass>,
    alias_ref<jbyteArray> key,
    alias_ref<jbyteArray> entity) {
  auto pinnedKey = key->pin();
  auto pinnedEntity = entity->pin();

  CryptoConfig config = pinnedKey.size() == 32
      ? CryptoConfig::CONFIG_256()
      : CryptoConfig::CONFIG_128();

  // we only need the slices to build the object, and then they can be discarded
  auto result = makeCxxInstance(
      config,
      Slice(reinterpret_cast<uint8_t*>(&pinnedKey[0]), pinnedKey.size()),
      Slice(reinterpret_cast<uint8_t*>(&pinnedEntity[0]), pinnedEntity.size()));

  pinnedEntity.abort();
  pinnedKey.abort();

  return result;
}

void DecryptHybrid::registerNatives() {
  registerHybrid({
    makeNativeMethod("initHybrid", DecryptHybrid::initHybrid),
    makeNativeMethod("start", DecryptHybrid::start),
    makeNativeMethod("read", DecryptHybrid::read),
    makeNativeMethod("end", DecryptHybrid::end),
  });
}

void DecryptHybrid::start(alias_ref<jbyteArray> header) {
  auto pinnedHeader = header->pin();
  decrypt_.start(Slice(reinterpret_cast<uint8_t*>(&pinnedHeader[0]), pinnedHeader.size()));
  pinnedHeader.abort();
}

void DecryptHybrid::read(
    alias_ref<jbyteArray> source,
    jint sourceOffset,
    alias_ref<jbyteArray> target,
    jint targetOffset,
    jint count) {
  if (facebook::jni::isSameObject(source, target)) {
    readSameBuffer(source, sourceOffset, targetOffset, count);
  } else {
    auto pinnedSource = source->pin();
    auto pinnedTarget = target->pin();
    Slice sourceSlice(reinterpret_cast<uint8_t*>(&pinnedSource[0]), pinnedSource.size());
    Slice targetSlice(reinterpret_cast<uint8_t*>(&pinnedTarget[0]), pinnedTarget.size());
    // Slice API will check boundaries
    decrypt_.read(
        sourceSlice(sourceOffset, sourceOffset + count),
        targetSlice(targetOffset, targetOffset + count));
    pinnedTarget.commit();
    pinnedSource.abort();
  }
}

void DecryptHybrid::readSameBuffer(
    alias_ref<jbyteArray> buffer,
    jint sourceOffset,
    jint targetOffset,
    jint count) {
  auto pinnedBuffer = buffer->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedBuffer[0]), pinnedBuffer.size());
  // Slice API will check boundaries
  decrypt_.read(
    slice(sourceOffset, sourceOffset + count),
    slice(targetOffset, targetOffset + count));
  pinnedBuffer.commit();
}

bool DecryptHybrid::end(alias_ref<jbyteArray> tail) {
  auto pinnedTail = tail->pin();
  bool verified = decrypt_.end(
      Slice(reinterpret_cast<uint8_t*>(&pinnedTail[0]), pinnedTail.size()));
      pinnedTail.abort();
  return verified;
}

DecryptHybrid::DecryptHybrid(Decrypt&& decrypt)
  : decrypt_(std::move(decrypt)) {}

DecryptHybrid::DecryptHybrid(CryptoConfig config, Slice key, Slice entity)
  : decrypt_(config, key, entity) {}

}}}
