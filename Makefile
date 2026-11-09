PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
CONFDIR ?= /etc/bannix
SYSTEMDDIR ?= /etc/systemd/system

.PHONY: all build release check test clean install update uninstall

all: build

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

test:
	cargo test

clean:
	cargo clean

install: release
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/bannix $(DESTDIR)$(BINDIR)/bannix
	install -d $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(CONFDIR)/jails.d
	test -f $(DESTDIR)$(CONFDIR)/bannix.toml || install -m 640 config/bannix.toml $(DESTDIR)$(CONFDIR)/bannix.toml
	install -m 640 config/jails.d/*.toml $(DESTDIR)$(CONFDIR)/jails.d/
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install -m 644 systemd/bannix.service $(DESTDIR)$(SYSTEMDDIR)/bannix.service
	systemctl daemon-reload || true

update: release
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/bannix $(DESTDIR)$(BINDIR)/bannix
	systemctl daemon-reload || true
	systemctl restart bannix 2>/dev/null || true

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/bannix
	rm -f $(DESTDIR)$(SYSTEMDDIR)/bannix.service
	systemctl daemon-reload || true

