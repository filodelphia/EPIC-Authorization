2pipe:
	rm -rf build/2pipe
	mkdir -p build/2pipe
	cd build/2pipe
	cmake $$SDE 											\
		-DCMAKE_MODULE_PATH="$$SDE/cmake/"					\
		-DCMAKE_INSTALL_PREFIX="$$SDE_INSTALL" 				\
		-DP4C=$$SDE_INSTALL/bin/p4c 						\
		-DP4_PATH=$$PWD/src/2-pipelines/multipipeline.p4	\
		-DP4_NAME=multipipeline								\
		-DP4_LANG=p4_16 									\
		-DTOFINO=ON
	
	$(MAKE) -j install