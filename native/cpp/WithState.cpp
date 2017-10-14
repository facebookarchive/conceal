// Copyright 2004-present Facebook. All Rights Reserved.

#include "WithState.h"
#include "CryptoException.h"

#include <stdexcept>

namespace facebook { namespace conceal {

WithState::WithState(State initial)
  : state_(initial) {}

void WithState::checkArgument(bool condition, const char *msg) {
  if (!condition) {
    state_ = State::ERROR;
    throw std::invalid_argument(msg);
  }
}

void WithState::checkState(State current, State newState, const char *what) {
  check(state_ == current, what);
  state_ = newState;
}

void WithState::check(bool condition, const char *what) {
  if (!condition) {
    state_ = State::ERROR;
    throw CryptoException(what);
  }
}

}}
