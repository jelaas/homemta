# Build a fully static homemta against musl libc.
#
# The only C/C++ code involved is musl libc itself and a handful of C/asm
# files inside the ring crate (compiled in at build time, no runtime
# library dependencies). If your toolchain is glibc-based, install
# musl-gcc and use `CC_x86_64_unknown_linux_musl=musl-gcc`.

TARGET ?= x86_64-unknown-linux-musl
PREFIX ?= /usr/local

CARGO ?= cargo

all:
	$(CARGO) build --release --target $(TARGET)

test:
	$(CARGO) test --target $(TARGET)

install: all
	install -Dm755 target/$(TARGET)/release/homemta $(DESTDIR)$(PREFIX)/sbin/homemta
	install -Dm644 homemta.jsonc.example $(DESTDIR)/etc/homemta.jsonc.example
	install -Dm644 contrib/homemta.service $(DESTDIR)/usr/lib/systemd/system/homemta.service

clean:
	$(CARGO) clean

.PHONY: all test install clean
