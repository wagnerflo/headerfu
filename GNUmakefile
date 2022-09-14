.SECONDEXPANSION:
.PHONY: test

test: tests/inifu.out tests/sslfu.out tests/httpfu.out tests/structfu.out
	@for test in $?; do $$test; done

sslfu_LDFLAGS := -lssl -lcrypto
httpfu_LDFLAGS := $(sslfu_LDFLAGS)
httpfu_DEPENDS := include/sslfu.hh

tests/%.out: tests/%.cc $(shell find -name *.hh) $$($$*_DEPENDS)
	@$(CXX) -std=c++17 -I include $($*_LDFLAGS) -o $@ $<
