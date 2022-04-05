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
#ifndef INIFU_HH
#define INIFU_HH

#include <string>
#include <fstream>
#include <functional>

namespace inifu {
  namespace detail {
    template<typename T>
    void assign(T& dest, const std::string& value) {
      dest = value;
    }

    template<>
    void assign(int& dest, const std::string& value) {
      dest = std::stoi(value);
    }
  }

  class syntax_error : public std::runtime_error {
    public:
      syntax_error(const std::string& msg)
        : std::runtime_error(msg) {
        /* empty */
      }
  };

  template<typename T> class bind {
    protected:
      const std::string key;
      T& dest;

    public:
      bind(const std::string& k, T& d) : key(k), dest(d) {
        /* empty */
      }

      void operator()(const std::string& key,
                      const std::string& value) const {
        if (key == this->key)
          detail::assign(dest, value);
      }
  };

  template<typename... F>
  void parse(std::istream&& infile, F&&... funcs) {
    std::string line, key, value;

    while(std::getline(infile, line)) {
      // trim line
      line = detail::trim(line);

      // ignore empty lines and comments
      if(line.empty() || line[0] == '#')
        continue;

      // split by "="
      if(!detail::split(line, "=", key, value))
        throw syntax_error(
          "Line '" + line + "' is missing equal sign.");

      // ...
      if (k.find_first_not_of(detail::header_key) != std::string::npos)
        throw std::runtime_error("Invalid charakter in header key");

      // quoted?
      if (value[0] == '"') {

      }
      // else if (value.find
      
      value = detail::trim(value);

      // run std::invoke over C++17 folded Callables
      (std::invoke(std::forward<F>(funcs), section, key, value), ...);
    }
  };

  template <typename... F>
  inline void parse(std::istream& infile, F&&... funcs) {
    parse(std::move(infile), funcs...);
  };
}

#endif /* INIFU_HH */
