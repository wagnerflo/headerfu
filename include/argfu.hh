/* Copyright 2022 Florian Wagner <florian@wagner-flo.net>
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
#ifndef ARGFU_HH
#define ARGFU_HH

#include <algorithm>
#include <iomanip>
#include <forward_list>
#include <functional>
#include <list>
#include <map>
#include <string>
#include <sstream>
#include <vector>

namespace argfu {

  typedef std::vector<std::string> arguments;

  namespace detail {
    class virtualvalueopt {
      public:
        virtual void set(const std::string&) = 0;
    };

    class virtualflagopt {
      public:
        virtual void set() = 0;
    };

    class virtualopt {
      public:
        virtual ~virtualopt() = default;
        virtual std::string help() const = 0;

        virtualvalueopt* valueopt() {
          return dynamic_cast<virtualvalueopt*>(this);
        }

        virtualflagopt* flagopt() {
          return dynamic_cast<virtualflagopt*>(this);
        }
    };

    template<typename T> class valueopt;
    template<typename T> class flagopt;

    typedef std::tuple<std::string,char,virtualopt*> optitem;
    typedef std::forward_list<optitem> optlist;
    typedef std::forward_list<virtualvalueopt*> arglist;

    virtualopt* find_opt(const char& key, const optlist& lst) {
      for (auto item : lst)
        if (std::get<1>(item) == key)
          return std::get<2>(item);
      return NULL;
    }

    virtualopt* find_opt(const std::string& key, const optlist& lst) {
      if (key.length() == 1)
        return find_opt(key[0], lst);
      for (auto item : lst)
        if (std::get<0>(item) == key)
          return std::get<2>(item);
      return NULL;
    }

    std::string format_key(const optitem&) {
      return "";
    }

    std::string format_help(const optitem&, std::string::size_type&) {
      return "";
    }
  }

  class parser {
    protected:
      const std::string& _progname;
      detail::optlist _opts;
      detail::arglist _args;

      template <template <typename> typename T, typename U>
      auto&& add_option(const std::string& l, const char s, U& r) {
        if (detail::find_opt(l, _opts) || find_opt(s, _opts))
          throw std::runtime_error("duplicate");
        auto opt = new T<U>(*this, r);
        _opts.emplace_front(l, s, opt);
        return std::move(*opt);
      }

    public:
      parser(parser&&) = default;
      parser(const std::string& p) : _progname(p) {
        /* empty */
      }

      ~parser() {
        for (auto o : _opts)
          delete std::get<2>(o);
      }

      void parse(const arguments& cmdline) const {
        auto it = cmdline.begin() + 1;

        for (; it != cmdline.end(); ++it) {
          const std::string& item = *it;

          // detect the end-of-options delimiter
          if (item == "--")
            break;

          std::string key, value;
          bool shortopt = false;

          // 1 hyphen at the start makes a short option
          if (auto pos = item.find_first_not_of('-'); pos == 1) {
            shortopt = true;
            key = item.substr(pos);
          }

          // 2 hyphens make a long option
          else if (pos == 2) {
            if(item.length() == 3)
              throw std::runtime_error("long option too short");

            // extract the key from the item; takes into account the
            // possibility of a key=value form
            pos = item.find("=", 2);
            key = item.substr(2, pos);
            if(pos != std::string::npos)
              value = item.substr(pos + 1);
          }

          // anything else is a value: but if we find one at this point
          // it means end-of-options; rewind and start parsing arguments
          else {
            break;
          }

          // handle short options with multiple characters; all but the
          // last option must be be flags
          if(shortopt && key.length() > 1) {
            auto it = std::as_const(key).begin();
            for (; it != key.end() - 1; ++it) {
              auto opt = detail::find_opt(*it, _opts);
              if (!opt)
                throw std::runtime_error("unknown flag");
              auto fopt = opt->flagopt();
              if (!fopt)
                throw std::runtime_error(
                  "non-flag at not-end of multi-char short option"
                );
              fopt->set();
            }
            // leave the last char as the key to be handled as normal
            key = *it++;
          }

          // select the matching option
          auto opt = detail::find_opt(key, _opts);
          if (!opt)
            throw std::runtime_error("unknown option");

          if (auto vopt = opt->valueopt()) {
            if (it++ == cmdline.end())
              throw std::runtime_error("");
            vopt->set(*it);
          }
          else if (auto fopt = opt->flagopt()) {
            fopt->set();
          }
        }

        // continue with arguments
        for (; it != cmdline.end(); ++it) {

        }
      }

      void parse(int const& argc, const char** const& argv) const {
        parse(arguments(argv, argv + argc));
      }

      template <typename T>
      auto&& option(const std::string& l, const char s, T& r) {
        return std::move(add_option<detail::valueopt>(l, s, r));
      }

      template<typename T>
      auto&& flag(const std::string& l, const char s, T& r) {
        return std::move(add_option<detail::flagopt>(l, s, r));
      }

      void usage(std::ostream& os) const {
        os << "Usage: " << _progname << std::endl;
      }

      void options(std::ostream& os) const {
        std::forward_list<std::pair<const detail::optitem&, std::string>> keys;
        std::string::size_type width = 23;

        for (const auto& opt: _opts) {
          auto& [_, key] = keys.emplace_front(opt, detail::format_key(opt));
          width = std::max(key.length(), width);
        }

        width++;

        os << "Options:" << std::endl;
        for (auto& [opt, key] : keys) {
          os << std::left << std::setw(static_cast<int>(width))
             << key
             << detail::format_help(opt, width)
             << std::endl;
        }
      }
  };

  namespace detail {
    template <typename T> const T _convert(const std::string& val) {
      T ret;
      std::istringstream iss(val);
      iss >> ret;
      return ret;
    }

    template <> const std::string _convert(const std::string& val) {
      return val;
    }

    template<typename T, typename U>
    class baseopt : public virtualopt {
      protected:
        parser& _parser;
        T& _ref;
        std::string _help;

      public:
        baseopt(baseopt<T,U>&&) = default;
        baseopt(parser& p, T& r) : _parser(p), _ref(r) {
          /* empty? */
        }

        operator parser&&() const {
          return std::move(_parser);
        }

        virtual std::string help() const {
          return _help;
        }

        U&& help(const std::string& h) {
          _help = h; return std::move(*static_cast<U*>(this));
        }

        template<typename V>
        auto&& option(const std::string& l, const char s, V& r) {
          return std::move(_parser.option(l, s, r));
        }

        template<typename V>
        auto&& flag(const std::string& l, const char s, V& r) {
          return std::move(_parser.flag(l, s, r));
        }
    };

    template<typename T>
    class valueopt : public baseopt<T, valueopt<T> > {
      protected:
        std::function<const T(const std::string&)> _converter = _convert<T>;
        std::forward_list<std::function<void(const T&)>*> _validators;

        virtual void set(const std::string& inp) {
          auto val = _converter(inp);
          for (auto func : std::as_const(_validators))
            (*func)(val);
          this->_ref = val;
        }

      public:
        using baseopt<T, valueopt<T> >::baseopt;

        ~valueopt() {
          for (auto v : _validators)
            delete v;
        }

        template <typename U> auto&& converter(U func) {
          _converter = func;
          return std::move(*this);
        }

        template <typename U> auto&& add_validator(U func) {
          _validators.emplace_front(new auto(func));
          return std::move(*this);
        }

        auto&& greater(const T& min) {
          add_validator([min](const T& val) {
            if (val <= min)
              throw std::runtime_error("");
          });
          return std::move(*this);
        }

        auto&& greater_equal(const T& min) {
          add_validator([min](const T& val) {
            if (val < min)
              throw std::runtime_error("");
          });
          return std::move(*this);
        }

        auto&& less(const T& max) {
          add_validator([max](const T& val) {
            if (val >= max)
              throw std::runtime_error("");
          });
          return std::move(*this);
        }

        auto&& less_equal(const T& max) {
          add_validator([max](const T& val) {
            if (val > max)
              throw std::runtime_error("");
          });
          return std::move(*this);
        }

        auto&& range(const T& min, const T& max) {
          return std::move(greater_equal(min).less_equal(max));
        }
    };

    template<typename T>
    class flagopt : public virtualflagopt, public baseopt<T, flagopt<T> > {
      protected:
        T _max = 0;

        void _set(bool const*) { this->_ref = true; }
        void _set(...)         { if (_max == 0 || this->_ref < _max) this->_ref++; }
        virtual void set()     { _set(static_cast<T const *>(0)); }

      public:
        using baseopt<T, flagopt<T> >::baseopt;

        auto&& max(const T& m) {
          _max = m; return std::move(this);
        }
    };
  }

  namespace detail {
    typedef int (&dispatch_target)(const std::string&, const arguments&);
    typedef std::initializer_list<
              std::pair<const std::string, detail::dispatch_target> > dispatch_targets;
  }

  int dispatch(const arguments& args, detail::dispatch_targets&& tgts) {
    if (tgts.size() == 0)
      throw std::runtime_error("argfu::dispatch requires at least one target");

    if (args.size() > 0) {
      auto progname = args.front();

      if (auto const pos = progname.find_last_of("/"); pos != std::string::npos)
        progname = progname.substr(pos + 1);

      for (auto target : tgts) {
        if (target.first == progname)
          return target.second(progname, args);
      }
    }

    auto primary = tgts.begin();
    return primary->second(primary->first, {});
  }

  int dispatch(int const& argc, const char** const& argv, detail::dispatch_targets&& tgts) {
    return dispatch(arguments(argv, argv + argc), std::move(tgts));
  }
}

#endif /* ARGFU_HH */
