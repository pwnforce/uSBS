ELF_DIR ?= /tmp/elf
IMAGE = usbs

.PHONY: build run

build:
	docker build -t $(IMAGE) $(shell pwd)

run: build
	mkdir -p $(ELF_DIR)
	docker run --rm  -it \
	  -v $(realpath $(ELF_DIR)):/elf \
	  -v $(realpath $(shell pwd)/usbs):/root/usbs \
	  $(IMAGE):latest
