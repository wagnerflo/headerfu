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
#ifndef SYSFU_HH
#define SYSFU_HH

#include <unistd.h>
#include <iostream>

namespace sysfu {

  namespace detail {
    template <typename T, typename S>
    inline int looprw(ssize_t(*func)(int, T*, size_t),
                      int fd, S* s, int n) {
      std::streamsize done = 0;
      size_t ret;
      do {
        ret = func(fd, s + done, n - done);
        if (ret == -1)
          throw std::system_error(errno, std::generic_category());
        else
          done += ret;
      }
      while(done < n);
      return done;
    };

  };

  namespace file {
    FILE* open(int fd, const char* mode) {
      FILE* fp = ::fdopen(fd, mode);
      if (!fp)
        throw std::system_error(errno, std::generic_category());
      return fp;
    };

    void close(int fd) {
      if (::close(fd))
        throw std::system_error(errno, std::generic_category());
    };

    void close(FILE* fp) {
      if (::fclose(fp))
        throw std::system_error(errno, std::generic_category());
    };

    void seek(int fd, off_t offset, int whence = SEEK_SET) {
      if (::lseek(fd, offset, whence) == -1)
        throw std::system_error(errno, std::generic_category());
    };

    void seek(FILE* fp, long offset, int whence = SEEK_SET) {
      if (::fseek(fp, offset, whence) == -1)
        throw std::system_error(errno, std::generic_category());
    };
  };

  class fdbuf : public std::streambuf {
    protected:
      int _fd;

    public:
      fdbuf(int fd) : _fd(fd) { /* empty */ };
      void close() { file::close(_fd); };
      int fileno() const { return _fd; };

    protected:
      // writing
      std::streamsize xsputn (const char* s, std::streamsize n) {
        return detail::looprw(&::write, _fd, s, n);
      };

      int_type overflow (int_type c) {
        const char buf = c;
        if (xsputn(&buf, 1))
          return c;
        return EOF;
      };

      // reading
      std::streamsize xsgetn (char* s, std::streamsize n) {
        return detail::looprw(&::read, _fd, s, n);
      };

      int_type underflow () {
        char buf = 0;
        if (xsgetn(&buf, 1))
          return buf;
        return EOF;
      };

      int_type uflow() {
        return 0;
      };
  };

  class fdostream : public std::ostream {
    protected:
      fdbuf _buf;
    public:
      fdostream(int fd) : _buf(fd), std::ostream(&_buf) { /* empty */ };
  };

  class fdistream : public std::istream {
    protected:
      fdbuf _buf;
    public:
      fdistream(int fd) : _buf(fd), std::istream(&_buf) { /* empty */ };
  };

  class pipe {
    protected:
      int RE = -1;
      int WE = -1;

    public:
      pipe() { /* empty */ };
      pipe(const pipe&) = delete;
      pipe& operator=(const pipe&) = delete;
      ~pipe() { close(); };

      void create() {
        if (is_created())
          throw std::runtime_error("twice");
        int fd[2];
        ::pipe(fd);
        RE = fd[0];
        WE = fd[1];
      };

      bool is_created() {
        return RE != -1 || WE != -1;
      };

      void connect_stdin() {
        if (!is_created())
          throw std::runtime_error("create first");
        ::dup2(RE, STDIN_FILENO);
        file::close(WE);
        file::close(RE);
        WE = -1;
        RE = -1;
      };

      fdistream prepare_reading() {
        if (!is_created())
          throw std::runtime_error("create first");
        if (RE == -1)
          throw std::runtime_error("already writing");
        if (WE != -1) {
          file::close(WE);
          WE = -1;
        }
        return fdistream(RE);
      };

      fdostream prepare_writing() {
        if (!is_created())
          throw std::runtime_error("create first");
        if (WE == -1)
          throw std::runtime_error("already reading");
        if (RE != -1) {
          file::close(RE);
          RE = -1;
        }
        return fdostream(WE);
      };

      void close() {
        if (RE != -1) {
          file::close(RE);
          RE = -1;
        }
        if (WE != -1) {
          file::close(WE);
          WE = -1;
        }
      }
  };
}

#endif /* SYSYFU_HH */
