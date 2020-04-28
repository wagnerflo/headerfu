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
    inline bool split(const std::string& in, const std::string& sep,
                      std::string& first, std::string& second) {
      size_t pos = in.find(sep);

      if(pos == std::string::npos)
        return false;

      first = in.substr(0, pos);
      second = in.substr(pos + sep.size(), in.size() - pos - sep.size());

      return true;
    }

    inline std::string trim(const std::string& str,
                            const std::string& whitespace = " \t\n\r\f\v") {
      size_t startpos = str.find_first_not_of(whitespace);
      size_t endpos = str.find_last_not_of(whitespace);

      // only whitespace, return empty
      if(startpos == std::string::npos || endpos == std::string::npos)
        return "";

      // trim leading and trailing whitespace
      return str.substr(startpos, endpos - startpos + 1);
    }

    template<typename T>
    void assign(T& dest, const std::string& value) {
      dest = value;
    }

    template<>
    void assign(int& dest, const std::string& value) {
      dest = std::stoi(value);
    }
  }

  class syntax_error : public std::runtime_error
  {
    public:
      syntax_error(const std::string& msg)
        : std::runtime_error(msg) {
        /* empty */
      }
  };

  template<typename T> class bind {
    protected:
      const std::string match_section;
      const std::string match_key;
      T& dest;

    public:
      bind(const std::string& ms, const std::string& mk, T& d)
        : match_section(ms), match_key(mk), dest(d) {
        /* empty */
      }

      bind(const std::string& mk, T& d)
        : match_key(mk), dest(d) {
        /* empty */
      }

      void operator()(const std::string& section,
                      const std::string& key,
                      const std::string& value) const {
        if (section == match_section && key == match_key)
          detail::assign(dest, value);
      }
  };

  template <typename... F>
  void parse(std::istream&& infile, F&&... funcs) {
    std::string line, section, key, value;

    while(std::getline(infile, line)) {
      // trim line
      line = detail::trim(line);

      // ignore empty lines and comments
      if(line.empty() || line[0] == '#')
        continue;

      // section
      if(line[0] == '[') {
        if(line[line.size() - 1] != ']')
          throw syntax_error(
            "Section line '" + line + "' is missing closing bracket.");

        section = detail::trim(line.substr(1, line.size() - 2));
        continue;
      }

      // entry: split by "=", trim and set
      if(!detail::split(line, "=", key, value))
        throw syntax_error(
          "Entry line '" + line + "' is missing equal sign.");

      key = detail::trim(key);
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
