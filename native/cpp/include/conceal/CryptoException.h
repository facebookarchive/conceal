// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <string>
#include <stdexcept>

namespace facebook { namespace conceal {

class CryptoException: public std::runtime_error {
 public:  
  CryptoException(const std::string &what) : runtime_error(what) {}
  ~CryptoException() noexcept {}
};

}}
