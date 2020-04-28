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
#ifndef HTTPFU_HH
#define HTTPFU_HH

#include <istream>
#include <string>
#include <map>

namespace httpfu {

  namespace detail {
    const std::string header_key(
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "0123456789!#$%&'*+-.^_`|~",
      77
    );
    const std::string not_header_value(
      "\00\01\02\03\04\05\06\07\10\12\13\14\15\16\17\20"
      "\21\22\23\24\25\26\27\30\31\32\33\34\35\36\37\177",
      32
    );
    const std::string sp(" ");
    const std::string ows(" \t");

    inline void gethttpline(std::istream& is, std::string& dest) {
      std::getline(is, dest, '\n');
      if (dest.empty() || dest.back() != '\r')
        throw std::runtime_error("Invalid HTTP line ending");
      dest.pop_back();
    }
  }

  class response {
    public:
      typedef std::multimap<const std::string,const std::string>
          headers_type;

    public:
      static response receive(std::istream& is) {
        response resp;
        std::string line;
        size_t pos, pos2;

        // Status line
        detail::gethttpline(is, line);

        // Version
        pos = line.find(detail::sp);
        if (pos == std::string::npos)
          throw std::runtime_error("Invalid status line");

        if (line.substr(0, pos) != "HTTP/1.1")
          throw std::runtime_error(
            "Unsupported HTTP version: " + line.substr(0, pos));

        // Code
        pos2 = line.find(detail::sp, pos + 1);
        if (pos2 == std::string::npos)
          throw std::runtime_error("Invalid status line");

        resp._status_code = std::stoul(line.substr(pos + 1, pos2));

        // Reason
        line = line.substr(pos2 + 1, line.length());
        if (line.empty())
          throw std::runtime_error("Invalid status line");

        resp._reason = line;

        // Headers
        while (1) {
          detail::gethttpline(is, line);
          if (line.empty())
            break;

          size_t pos = line.find(':');

          if (pos == std::string::npos)
            throw std::runtime_error("");

          size_t trimstart = line.find_first_not_of(detail::ows, pos + 1);
          size_t trimend = line.find_last_not_of(detail::ows);

          if (trimstart == std::string::npos)
            throw std::runtime_error("");

          for (int i=0; i < pos; i++)
            line[i] = ::tolower(line[i]);

          resp._headers.emplace(
            line.substr(0, pos),
            line.substr(trimstart, trimend - trimstart + 1)
          );
        }

        // Body
        auto cl = resp._headers.find("content-length");
        if (cl != resp._headers.end()) {
          auto bodylen = std::stoul(cl->second);
          resp._body.resize(bodylen);
          is.read(const_cast<char*>(resp._body.c_str()), bodylen);
        }

        return resp;
      };

      const unsigned int& status_code() const {
        return _status_code;
      };

      const std::string& reason() const {
        return _reason;
      };

      const headers_type& headers() const {
        return _headers;
      };

      const std::string& body() const {
        return _body;
      };

    protected:
      unsigned int _status_code;
      std::string _reason;
      headers_type _headers;
      std::string _body;
  };

  class request {
    protected:
      std::string _method;
      std::string _path;
      std::string _headers;
      std::string _body;

    public:
      request(const std::string& m, const std::string& p)
        : _method(m), _path(p), _headers("\r\n") {
        /* empty */
      };

      static request get(const std::string& p) {
        return request("GET", p);
      };

      inline void header(const std::string& k,
                         const std::string& v) & {
        if (k.find_first_not_of(detail::header_key) != std::string::npos)
          throw std::runtime_error("Invalid charakter in header key");

        if (v.find_first_of(detail::not_header_value) != std::string::npos)
          throw std::runtime_error("Invalid charakter in header value");

        _headers += k + ": " + v + "\r\n";
      };

      inline void body(const std::string& b) & {
        _body = b;
      }

      inline request&& header(const std::string& k,
                              const std::string& v) && {
        header(k, v);
        return std::move(*this);
      };

      inline request&& body(const std::string& b) && {
        body(b);
        return std::move(*this);
      };

      response send(std::iostream& ios) {
        ios << *this;
        return response::receive(ios);
      };

      friend std::ostream& operator<<(std::ostream& os, const request& req) {
        return os
          << req._method << " " << req._path << " HTTP/1.1"
          << req._headers
          << "Content-Length: " << req._body.length() << "\r\n"
          << "\r\n"
          << req._body;
      }
  };

}

#endif /* HTTPFU_HH */
