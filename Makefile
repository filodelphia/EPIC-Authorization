2pipe:
	rm -rf build/2pipe
	mkdir -p build/2pipe
	cmake $$SDE/p4studio -B build/2pipe						\
		-DCMAKE_MODULE_PATH="$$SDE/cmake/"					\
		-DCMAKE_INSTALL_PREFIX="$$SDE_INSTALL" 				\
		-DP4C=$$SDE_INSTALL/bin/p4c 						\
		-DP4_PATH=$$PWD/src/2-pipelines/multipipeline.p4	\
		-DP4_NAME=multipipeline								\
		-DP4_LANG=p4_16 									\
		-DTOFINO=ON
	
	make -C build/2pipe -j"$(nproc)" -l"$(nproc)" install