CC		:= gcc
CFLAGS	:=
LDFLAGS	:= -fPIC -shared
INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr/

all: plugin

plugin: netfilter_openvpn.c
	$(CC) $(CFLAGS) $(LDFLAGS) -I. -c netfilter_openvpn.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,netfilter_openvpn.so -o netfilter_openvpn.so netfilter_openvpn.o

install: plugin
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 netfilter_openvpn.so $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 netfilter.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m600 duo_openvpn.conf.inc $(DESTDIR)/etc/duo_openvpn.conf

clean:
	rm -f *.o
	rm -f *.so
	rm -f *.pyc
	rm -rf __pycache__
