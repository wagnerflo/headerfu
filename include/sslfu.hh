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
#ifndef SSLFU_HH
#define SSLFU_HH

#include <istream>
#include <streambuf>
#include <string>
#include <stdexcept>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>

namespace sslfu {

  namespace detail {

    template <typename T, typename S>
    inline int looprw(const std::string& op,
                      int(*func)(BIO*, T*, int),
                      BIO* bio, S* s, int n) {
      std::streamsize done = 0;
      int ret;
      do {
        ret = func(bio, s + done, n - done);
        if (ret > 0)
          done += ret;
        else if (ret == -2)
          throw std::system_error(
              ENOSYS, std::generic_category(),
              "BIO_" + op + " not implemented for this BIO*");
        else if (!BIO_should_retry(bio))
          break;
      }
      while(done < n);
      return done;
    };

    class biobuf : public std::streambuf {
      protected:
        BIO* _bio = 0;

      public:
        biobuf() { /* empty */ };
        biobuf(const biobuf&) = delete;
        biobuf& operator=(const biobuf&) = delete;
        ~biobuf() { close(); };

        void close() {
          BIO_free_all(_bio);
          _bio = 0;
        };

        BIO* bio() const { return _bio; };
        BIO* bio(BIO* b) { return _bio = b; };

      protected:
        // writing
        std::streamsize xsputn (const char* s, std::streamsize n) {
          return detail::looprw("write", &BIO_write, _bio, s, n);
        };

        int_type overflow (int_type c) {
          const char buf = c;
          if (xsputn(&buf, 1))
            return c;
          return EOF;
        };

        // reading
        std::streamsize xsgetn (char* s, std::streamsize n) {
          return detail::looprw("read", &BIO_read, _bio, s, n);
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

  };

  class openssl_error : public std::runtime_error {
    protected:
      class queue_item {
        public:
          const unsigned long code;
          const char* lib;
          const char* func;
          const char* reason;

          queue_item(const unsigned long& c)
            : code(c),
              lib(ERR_lib_error_string(c)),
              func(ERR_func_error_string(c)),
              reason(ERR_reason_error_string(c)) {
            /* empty */
          };

          const std::string what() const {
            std::string ret;
            if (func) {
              ret += func;
              ret += " ";
            }
            return ret + "in " + lib + ": " + reason;
          };
      };
      const std::vector<queue_item> queue;

      openssl_error
          (const std::string& w, const std::vector<queue_item>& q)
            : std::runtime_error(construct_what(w, q)), queue(q) {
        /* empty */
      };

      static const std::string construct_what
          (const std::string& w,
           const std::vector<queue_item>& q) {
        std::string what_arg = w;
        for (auto item : q) {
          what_arg += "\n    " + item.what();
        }
        return what_arg;
      };

    public:
      openssl_error(openssl_error&& o)
        : std::runtime_error(o.what()), queue(std::move(o.queue)) {
        /* empty */
      };

      static openssl_error with_error_queue(const std::string& what) {
        std::vector<queue_item> q;
        unsigned long err = 0;
        while((err = ERR_get_error()) != 0) {
          q.push_back(queue_item(err));
        }
        return openssl_error(what, q);
      };
  };

  class clientstream : public std::iostream {
    protected:
      SSL_CTX* _ctx = 0;
      BIO* _conn = 0;
      SSL *_ssl = 0;
      detail::biobuf _buf;

      std::string _ciphers =
        "HIGH:!aNULL:!eNULL:!EXP:!DSS:!kRSA:!PSK:!SRP:!MD5:!RC4:!SHA:"
        "!SEED:!ECDSA:!ADH:!IDEA";
      long _options = SSL_OP_ALL | SSL_OP_NO_COMPRESSION;
      int _verify_mode = SSL_VERIFY_PEER;
      int _verify_depth = 8;
      std::string _CAfile;
      std::string _CApath;
      std::string _cert;

    public:
      clientstream()
          : std::iostream(&_buf),
            _CAfile(X509_get_default_cert_file()),
            _CApath(X509_get_default_cert_dir()) {
        SSL_library_init();
        SSL_load_error_strings();
        OPENSSL_config(0);
      };

      clientstream(const std::string& hostname, const std::string& port)
          : clientstream() {
        connect(hostname, port);
      };

      ~clientstream() {
        SSL_CTX_free(_ctx);
      };

      void CAfile (const std::string&& val) { _CAfile = val; };
      void CApath (const std::string&& val) { _CApath = val; };
      void cert   (const std::string&& val) { _cert   = val; };

      void connect(const std::string& hostname, const std::string& port) {
        ERR_clear_error();

        const SSL_METHOD* method = TLS_client_method();
        if (method == 0)
          throw openssl_error::with_error_queue(
            "Error constructing OpenSSL SSL_METHOD");

        _ctx = SSL_CTX_new(method);
        if (_ctx == 0)
          throw openssl_error::with_error_queue(
              "Error constructing OpenSSL SSL_CTX");

        if (SSL_CTX_set_min_proto_version(_ctx, TLS1_2_VERSION) != 1)
          throw openssl_error::with_error_queue(
              "Error setting TLSv1.2 as minimum protocol version");

        SSL_CTX_set_options(_ctx, _options);
        SSL_CTX_set_verify(_ctx, _verify_mode, 0);
        SSL_CTX_set_verify_depth(_ctx, _verify_depth);

        if (SSL_CTX_load_verify_locations(
              _ctx,
              _CAfile.empty() ? 0 : _CAfile.c_str(),
              _CApath.empty() ? 0 : _CApath.c_str()) != 1)
          throw openssl_error::with_error_queue(
            "Error loading CAfile and/or CApath");

        if (!_cert.empty()) {
          if (SSL_CTX_use_certificate_file(
                _ctx, _cert.c_str(), SSL_FILETYPE_PEM) != 1)
            throw openssl_error::with_error_queue(
              "Error loading client certificate");
        }

        _conn = BIO_new_ssl_connect(_ctx);
        if (_conn == 0)
          throw openssl_error::with_error_queue(
            "Error constructing SSL connection");

        BIO_set_conn_hostname(_conn, hostname.c_str());
        BIO_set_conn_port(_conn, port.c_str());

        BIO_get_ssl(_conn, &_ssl);
        if (_ssl == 0)
          throw openssl_error::with_error_queue(
            "Error retrieving SSL pointer from connection");

        X509_VERIFY_PARAM* param = SSL_get0_param(_ssl);

        #ifndef LIBRESSL_VERSION_NUMBER
        X509_VERIFY_PARAM_set_hostflags(
          param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        #endif

        if (X509_VERIFY_PARAM_set1_host(
              param, hostname.c_str(), hostname.length()) != 1)
          throw openssl_error::with_error_queue(
            "Error setting hostname for certificate verification");

        if (SSL_set_cipher_list(_ssl, _ciphers.c_str()) != 1)
          throw openssl_error::with_error_queue(
            "Error setting SSL ciphers");

        if (SSL_set_tlsext_host_name(_ssl, hostname.c_str()) != 1)
          throw openssl_error::with_error_queue(
            "Error setting SNI ClientHello value");

        if (BIO_do_connect(_conn) != 1)
          throw openssl_error::with_error_queue(
            "Error opening connection");

        if (BIO_do_handshake(_conn) != 1)
          throw openssl_error::with_error_queue(
            "Error on SSL handshake");

        _buf.bio(_conn);
      };
  };

}

#endif /* SSLFU_HH */
