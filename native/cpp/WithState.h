// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

namespace facebook { namespace conceal {

class WithState {
 protected:
   enum State {
       INITIAL,  // constructed: start() ->
       PROGRESS, // writing/reading content: end() ->
       ENDED,    // finished
       ERROR };  // error in the way

   WithState(State initial);
   void checkArgument(bool condition, const char *msg);
   void checkState(State current, State newState, const char *what);
   void check(bool condition, const char *what);

 private:
   State state_;
};

}}
