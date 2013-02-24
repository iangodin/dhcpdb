
default: build
	make -C build

build:
	mkdir -p build
	cd build ; cmake ..

install:
	make -C build install

