DESTDIR = /usr
SRCDIR = target/release
INSTALL_PATH = $(DESTDIR)/bin
EXECUTABLE = barnowld

SRC_SERVICEDIR = config
DST_SERVICEDIR = /etc/systemd/system
SERVICEFILE = barnowld.service


all: build docker

build:
	cargo build

musl: container/barnowld
	cargo build --target=x86_64-unknown-linux-musl 
	strip target/x86_64-unknown-linux-musl/debug/barnowld -o container/barnowld


docker: musl
	docker build -t barnowld container 

release:
	cargo build --release

clippy:
	cargo clippy

clean:
	cargo clean

run:
	cargo run

test: build
	cargo test

format:
	rustfmt src/*

format-check:
	cargo fmt --all -- --check

get-pocs:
	@mkdir poc
	git clone https://github.com/crozone/SpectrePoC.git poc/spectre-poc
	git clone https://github.com/paboldin/meltdown-exploit.git meldown-poc
	git clone https://github.com/sslab-gatech/DrK.git drk-poc
	git clone https://github.com/DanGe42/flush-reload.git flush-reload-poc
	git clone https://github.com/Miro-H/CacheSC.git cache-sc-poc
	git clone https://github.com/PittECEArch/AdversarialPrefetch.git adversarial-prefetch-poc
	git clone https://github.com/Anton-Cao/spectrev2-poc.git spectrev2-poc

install: release
	@echo Install barnowld executable to $(INSTALL_PATH)
	sudo install -D -m 755 $(SRCDIR)/$(EXECUTABLE) $(INSTALL_PATH)/$(EXECUTABLE)
	@echo Install systemd service file to $(DST_SERVICEDIR)
	sudo install -D -m 644 $(SRC_SERVICEDIR)/$(SERVICEFILE) $(DST_SERVICEDIR)/$(SERVICEFILE)
	$(MAKE) help-service

uninstall:
	rm -rf $(INSTALL_PATH)/$(EXECUTABLE)
	rm -rf $(DST_SERVICEDIR)/$(SERVICEFILE)

help-service:
	@echo
	@echo The installation routine did *not* activate the service.
	@echo Short reminder how to deal with newly installed service files - helpful systemd commands
	@echo
	@echo sudo systemctl daemon-reload
	@echo sudo systemctl enable $(SERVICEFILE)
	@echo sudo systemctl start $(SERVICEFILE)
	@echo sudo systemctl status $(SERVICEFILE)
	@echo sudo systemctl stop $(SERVICEFILE)
	@echo sudo journalctl -u $(SERVICEFILE) -f


.PHONY: build install uninstall help-service get-pocs format-check format test clean clippy musl
