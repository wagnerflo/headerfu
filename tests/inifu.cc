/* Copyright 2020 Florian Wagner <florian@wagner-flo.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fstream>
#include <cassert>
#include <functional>
#include "inifu.hh"

void test_bind () {
  std::string some_str, another_str, trimmed_str;
  int some_int = 0, another_int = 0, trimmed_int = 0;

  inifu::parse(
    std::ifstream("tests/inifu.valid.conf"),
    inifu::bind("some_str", some_str),
    inifu::bind("some_int", some_int),
    inifu::bind("sp3c14|_ c#4r4c73r2", "another_str", another_str),
    inifu::bind("sp3c14|_ c#4r4c73r2", "another_int", another_int),
    inifu::bind("whitespace aplenty", "Baby, I Wanna Trim", trimmed_str),
    inifu::bind("whitespace aplenty", "And Also Your Integers", trimmed_int)
  );

  assert(some_str == "I like = signs");
  assert(some_int == 42);
  assert(another_str == "I also like [ signs");
  assert(another_int == 4242);
  assert(trimmed_str == "Your Whitespace");
  assert(trimmed_int == 424242);
}

#define CALLBACK_ARGUMENTS const std::string&, const std::string&, const std::string&
int lambda, function, functor, method;

void test_callback_function(CALLBACK_ARGUMENTS) {
  function++;
}

class Functor {
  public:
    void operator()(CALLBACK_ARGUMENTS) {
      functor++;
    }
};

class CallbackCls {
  public:
    void method(CALLBACK_ARGUMENTS) {
      ::method++;
    }
};

void test_callback() {
  using namespace std::placeholders;

  lambda = 0;
  function = 0;
  functor = 0;
  method = 0;

  void (*function_pointer)(CALLBACK_ARGUMENTS) = &test_callback_function;
  void (&function_reference)(CALLBACK_ARGUMENTS) = test_callback_function;
  CallbackCls obj;
  auto bind_method = std::bind(&CallbackCls::method, &obj, _1, _2, _3);
  auto std_function = std::function<void(CALLBACK_ARGUMENTS)>(bind_method);

  inifu::parse(
    std::ifstream("tests/inifu.valid.conf"),
    // lambda
    [](CALLBACK_ARGUMENTS) {
      lambda++;
    },
    // function pointer
    function_pointer,
    // function reference
    function_reference,
    // functor
    Functor(),
    // std::bind with method pointer
    bind_method,
    // std::function containing std::bind with method pointer
    std_function
  );

  assert(lambda == 6);
  assert(function == 12);
  assert(functor == 6);
  assert(method == 12);
}

void test_malformed() {
  lambda = 0;
  std::ifstream conf = std::ifstream("tests/inifu.malformed.conf");
  auto func = [](CALLBACK_ARGUMENTS){ lambda++; };
  try {
    inifu::parse(conf, func);
  }
  catch(inifu::syntax_error& exc) {
    assert(
      std::string(exc.what()) ==
      "Entry line 'this line has no equal sign' is missing equal sign."
    );
  }
  catch(...) {
    assert(false);
  }
  try {
    inifu::parse(conf, func);
  }
  catch(inifu::syntax_error& exc) {
    assert(
      std::string(exc.what()) ==
      "Section line '[a sad section missing its closing bracket' is missing closing bracket."
    );
  }
  catch(...) {
    assert(false);
  }

  inifu::parse(conf, func);
  assert(lambda == 0);
}

int main() {
  test_bind();
  test_callback();
  test_malformed();
  return 0;
}
