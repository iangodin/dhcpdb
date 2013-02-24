
default: build
	make -C build

build:
	mkdir -p build
	cd build ; cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..

install:
	make -C build install

