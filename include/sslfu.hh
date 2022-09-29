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
#include <memory>
#include <streambuf>
#include <string>
#include <stdexcept>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

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
      std::string construct_what(const std::string& w, unsigned long c) const {
        const char* lib = ERR_lib_error_string(c);
        const char* func = ERR_func_error_string(c);
        const char* reason = ERR_reason_error_string(c);
        std::string ret = w + ": ";
        if (func) {
          ret += func;
          ret += " ";
        }
        return ret + "in " + lib + ": " + reason;
      };

      unsigned long clear_error_queue() const {
         unsigned long err = ERR_get_error();
        if (!err)
          throw std::runtime_error("Bla");
        ERR_clear_error();
         return err;
      };

    public:
      const unsigned long code;
      openssl_error(const std::string& w, const unsigned long c)
        : code(c), std::runtime_error(construct_what(w, c)) { /* empty */ };
      openssl_error(const std::string& w)
        : openssl_error(w, clear_error_queue()) { /* empty */ };
  };

  namespace detail {
    template<typename T, int(&UPREF)(T*), void(&FREE)(T*)>
    class refcntobj {
      protected:
        T* _ptr = 0;
      public:
        refcntobj() { /* empty */ };
        refcntobj(const refcntobj& o) : _ptr(o._ptr) { UPREF(_ptr); };
        refcntobj& operator=(const refcntobj& o) {
          FREE(_ptr); _ptr = o._ptr; UPREF(_ptr); return *this;
        };
        ~refcntobj() { FREE(_ptr); };
        T* ptr() const { return _ptr; };
    };
  };

  class pkey : public detail::refcntobj<EVP_PKEY,EVP_PKEY_up_ref,EVP_PKEY_free> {
    public:
      using detail::refcntobj<EVP_PKEY,EVP_PKEY_up_ref,EVP_PKEY_free>::refcntobj;
      pkey(FILE* fp) {
        _ptr = PEM_read_PrivateKey(fp, 0, 0, 0);
        if (!_ptr)
          throw openssl_error("Error loading private key");
      };
  };

  class x509 : public detail::refcntobj<X509,X509_up_ref,X509_free> {
    public:
      typedef std::vector<x509> chain;

      using detail::refcntobj<X509,X509_up_ref,X509_free>::refcntobj;
      x509(FILE* fp) {
        _ptr = PEM_read_X509(fp, 0, 0, 0);
        if (!_ptr)
          throw openssl_error("Error loading certificate");
      };

      static chain load_chain(FILE* fp) {
        chain c;
        while (1) {
          try {
            c.emplace_back(fp);
          }
          catch (openssl_error& exc) {
            if (exc.code != 167768172)
              throw exc;
            break;
          }
        }
        return c;
      };
  };

  class clientstream : public std::iostream {
    protected:
      SSL_CTX* _ctx = 0;
      BIO* _conn = 0;
      SSL* _ssl = 0;
      detail::biobuf _buf;

      std::string _ciphers =
        "HIGH:!aNULL:!eNULL:!EXP:!DSS:!kRSA:!PSK:!SRP:!MD5:!RC4:!SHA:"
        "!SEED:!ECDSA:!ADH:!IDEA";
      long _options = SSL_OP_ALL | SSL_OP_NO_COMPRESSION;
      int _verify_mode = SSL_VERIFY_PEER;
      int _verify_depth = 8;
      bool _load_default_verify = true;
      x509::chain _cachain;
      std::shared_ptr<x509> _clcert = 0;
      std::shared_ptr<pkey> _clpkey = 0;

    public:
      clientstream() : std::iostream(&_buf) {
        /* empty */
      };

      clientstream(const std::string& hostname, const std::string& port)
          : clientstream() {
        connect(hostname, port);
      };

      ~clientstream() {
        SSL_CTX_free(_ctx);
      };

      void disable_default_verify() {
        _load_default_verify = false;
      };
      void cacert (const x509& c) {
        _cachain.resize(std::max(_cachain.size(), x509::chain::size_type(1)));
        _cachain[0] = c;
      };
      void cacert (const x509::chain& c) {
        _cachain = c;
      };
      void clcert (const x509& c, const pkey& p) {
        _clcert = std::make_shared<x509>(c);
        _clpkey = std::make_shared<pkey>(p);
      };

      void connect(const std::string& hostname, const std::string& port) {
        ERR_clear_error();

        const SSL_METHOD* method = TLS_client_method();
        if (method == 0)
          throw openssl_error("Error constructing OpenSSL SSL_METHOD");

        _ctx = SSL_CTX_new(method);
        if (_ctx == 0)
          throw openssl_error("Error constructing OpenSSL SSL_CTX");

        if (SSL_CTX_set_min_proto_version(_ctx, TLS1_2_VERSION) != 1)
          throw openssl_error(
              "Error setting TLSv1.2 as minimum protocol version");

        SSL_CTX_set_options(_ctx, _options);
        SSL_CTX_set_verify(_ctx, _verify_mode, 0);
        SSL_CTX_set_verify_depth(_ctx, _verify_depth);

        if (_load_default_verify &&
            SSL_CTX_set_default_verify_paths(_ctx) != 1)
          throw openssl_error(
            "Error loading default CA file and path");

        X509_STORE* store = SSL_CTX_get_cert_store(_ctx);
        for (auto cert : _cachain)
          if (X509_STORE_add_cert(store, cert.ptr()) != 1)
            throw openssl_error("Error installing verification chain");

        if (_clcert && _clpkey) {
          if (SSL_CTX_use_certificate(_ctx, _clcert->ptr()) != 1)
            throw openssl_error(
              "Error loading client certificate");
          if (SSL_CTX_use_PrivateKey(_ctx, _clpkey->ptr()) != 1)
            throw openssl_error(
              "Error loading client certificate private key");
          if (SSL_CTX_check_private_key(_ctx) != 1)
            throw openssl_error(
              "Client certificate and/or private key invalid");
        }

        _conn = BIO_new_ssl_connect(_ctx);
        if (_conn == 0)
          throw openssl_error("Error constructing SSL connection");

        BIO_set_conn_hostname(_conn, hostname.c_str());
        BIO_set_conn_port(_conn, port.c_str());

        BIO_get_ssl(_conn, &_ssl);
        if (_ssl == 0)
          throw openssl_error(
            "Error retrieving SSL pointer from connection");

        X509_VERIFY_PARAM* param = SSL_get0_param(_ssl);

        #ifndef LIBRESSL_VERSION_NUMBER
        X509_VERIFY_PARAM_set_hostflags(
          param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        #endif

        if (X509_VERIFY_PARAM_set1_host(
              param, hostname.c_str(), hostname.length()) != 1)
          throw openssl_error(
            "Error setting hostname for certificate verification");

        if (SSL_set_cipher_list(_ssl, _ciphers.c_str()) != 1)
          throw openssl_error("Error setting SSL ciphers");

        if (SSL_set_tlsext_host_name(_ssl, hostname.c_str()) != 1)
          throw openssl_error("Error setting SNI ClientHello value");

        if (BIO_do_connect(_conn) != 1)
          throw openssl_error("Error opening connection");

        if (BIO_do_handshake(_conn) != 1)
          throw openssl_error("Error on SSL handshake");

        _buf.bio(_conn);
      };
  };

}

#endif /* SSLFU_HH */
