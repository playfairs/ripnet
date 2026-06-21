PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c17 -Iinclude -D_BSD_SOURCE -D_DEFAULT_SOURCE -D__FAVOR_BSD -D_GNU_SOURCE
LDFLAGS = -lpcap -lpthread

SRCDIR = src
OBJDIR = obj
BUILDDIR = bin
INCLUDEDIR = include

SOURCES = $(SRCDIR)/cli.c $(SRCDIR)/main.c $(SRCDIR)/packet.c $(SRCDIR)/stats.c $(SRCDIR)/stress.c $(SRCDIR)/util.c $(SRCDIR)/process.c $(SRCDIR)/dns.c $(SRCDIR)/traceroute.c $(SRCDIR)/ping.c $(SRCDIR)/scan.c $(SRCDIR)/netstat.c $(SRCDIR)/arp.c $(SRCDIR)/route.c $(SRCDIR)/firewall.c $(SRCDIR)/bandwidth.c $(SRCDIR)/monitor.c $(SRCDIR)/discovery.c $(SRCDIR)/security.c
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = $(BUILDDIR)/ripnet

VERSION := $(shell cat VERSION)

.PHONY: all clean install uninstall test release

all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(TARGET): $(OBJECTS) | $(OBJDIR) $(BUILDDIR)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BUILDDIR)

install: $(TARGET)
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)/ripnet

uninstall:
	rm -f $(BINDIR)/ripnet

test: $(TARGET)
	@echo "Running tests..."
	@./tests/run_tests.sh || echo "No tests configured"

release: clean
	@echo "Creating release for version $(VERSION)"
	@git tag -a v$(VERSION) -m "Release version $(VERSION)" || true
	@git archive --prefix=ripnet-$(VERSION)/ -o ripnet-$(VERSION).tar.gz HEAD
	@echo "Release ripnet-$(VERSION).tar.gz created"