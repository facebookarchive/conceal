// Copyright 2004-present Facebook. All Rights Reserved.

#include "EncryptHybrid.h"
#include "JavaArrays.h"

using facebook::jni::isSameObject;

namespace facebook { namespace conceal { namespace jni {

local_ref<EncryptHybrid::jhybriddata> EncryptHybrid::initHybrid(
    alias_ref<jclass>,
    alias_ref<jbyteArray> key,
    alias_ref<jbyteArray> iv,
    alias_ref<jbyteArray> entity) {
  auto pinnedKey = key->pin();
  auto pinnedIv = iv->pin();
  auto pinnedEntity = entity->pin();

  CryptoConfig config = pinnedKey.size() == 32
      ? CryptoConfig::CONFIG_256()
      : CryptoConfig::CONFIG_128();

  // we only need the slices to build the object, and then they can be discarded
  auto result = makeCxxInstance(
      config,
      Slice(reinterpret_cast<uint8_t*>(&pinnedKey[0]), pinnedKey.size()),
      Slice(reinterpret_cast<uint8_t*>(&pinnedIv[0]), pinnedIv.size()),
      Slice(reinterpret_cast<uint8_t*>(&pinnedEntity[0]), pinnedEntity.size()));

  pinnedEntity.abort();
  pinnedIv.abort();
  pinnedKey.abort();

  return result;
}

void EncryptHybrid::registerNatives() {
  registerHybrid({
    makeNativeMethod("initHybrid", EncryptHybrid::initHybrid),
    makeNativeMethod("start", EncryptHybrid::start),
    makeNativeMethod("write", "([BI[BII)V", EncryptHybrid::write),
    makeNativeMethod("end", EncryptHybrid::end),
  });
}

local_ref<jbyteArray> EncryptHybrid::start() {
  Slice header = encrypt_.start();
  return slice2JavaArray(header);
}

void EncryptHybrid::write(
    alias_ref<jbyteArray> source,
    jint sourceOffset,
    alias_ref<jbyteArray> target,
    jint targetOffset,
    jint count) {
  auto pinnedSource = source->pin();
  auto pinnedTarget = target->pin();
  Slice sourceSlice(reinterpret_cast<uint8_t*>(&pinnedSource[0]), pinnedSource.size());
  Slice targetSlice(reinterpret_cast<uint8_t*>(&pinnedTarget[0]), pinnedTarget.size());
  // Slice API will check the boundaries
  encrypt_.write(
      sourceSlice(sourceOffset, sourceOffset + count),
      targetSlice(targetOffset, targetOffset + count));
  pinnedTarget.commit();
  pinnedSource.abort();
}

void EncryptHybrid::writeSameBuffer(
    alias_ref<jbyteArray> buffer,
    jint sourceOffset,
    jint targetOffset,
    jint count) {
  auto pinnedBuffer = buffer->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedBuffer[0]), pinnedBuffer.size());
  // Slice API will check the boundaries
  encrypt_.write(
      slice(sourceOffset, sourceOffset + count),
      slice(targetOffset, targetOffset + count));
  pinnedBuffer.commit();
}

local_ref<jbyteArray> EncryptHybrid::end() {
  Slice tail = encrypt_.end();
  return slice2JavaArray(tail);
}

EncryptHybrid::EncryptHybrid(Encrypt&& encrypt)
  : encrypt_(std::move(encrypt)) {}

EncryptHybrid::EncryptHybrid(CryptoConfig config, Slice key, Slice iv, Slice entity)
  : encrypt_(config, key, iv, entity) {}

}}}
