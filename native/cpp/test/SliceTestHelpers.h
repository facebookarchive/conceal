// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <conceal/Slice.h>
#include <conceal/Buffer.h>

// Helper functions for tests

namespace facebook { namespace conceal {

void fillRange(Slice slice);

Buffer hex2Buffer(const char* hex);

}}
