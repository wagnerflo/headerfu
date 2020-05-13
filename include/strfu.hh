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
#ifndef STRFU_HH
#define STRFU_HH

#include <string>

namespace strfu {

  namespace detail {
    void find_and_replace_inplace(
      std::string& in, const std::string& s, const std::string& r) {
      size_t pos = 0;
      while ((pos = in.find(s, pos)) != std::string::npos) {
        in.replace(pos, s.length(), r);
        pos += r.length();
      }
    };
  };

  class str : public std::string {
    public:
      using std::string::string;

      str& replace(const std::string& s, const std::string& r) {
        detail::find_and_replace_inplace(*this, s, r);
        return *this;
      };
  };

  template<typename S, typename R>
  std::string replace(const std::string& in, const S& s, const R& r) {
    std::string ret(in);
    detail::find_and_replace_inplace(ret, s, r);
    return ret;
  };

  template<typename... Str> std::string concat(Str&&... strs) {
    std::string ret;
    ((ret += std::forward<Str>(strs)), ...);
    return ret;
  };
}

#endif /* STRFU_HH */
