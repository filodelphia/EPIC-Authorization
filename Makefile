default: dualpipe

dualpipe:
	rm -rf build/dualpipe
	mkdir -p build/dualpipe
	cmake $$SDE/p4studio -B build/dualpipe				\
		-DCMAKE_MODULE_PATH="$$SDE/cmake/"				\
		-DCMAKE_INSTALL_PREFIX="$$SDE_INSTALL" 			\
		-DP4C=$$SDE_INSTALL/bin/p4c 					\
		-DP4_PATH=$$PWD/src/dualpipeline/dualpipe.p4	\
		-DP4_NAME=dualpipe								\
		-DP4_LANG=p4_16 								\
		-DTOFINO=ON
	
	make -C build/dualpipe -j"$(nproc)" -l"$(nproc)" install

ds:
	make dualpipeds

dualpipeds:
	rm -rf build/dualpipeds
	mkdir -p build/dualpipeds
	cmake $$SDE/p4studio -B build/dualpipeds				\
		-DCMAKE_MODULE_PATH="$$SDE/cmake/"					\
		-DCMAKE_INSTALL_PREFIX="$$SDE_INSTALL" 				\
		-DP4C=$$SDE_INSTALL/bin/p4c 						\
		-DP4_PATH=$$PWD/src/dualpipeline-DS/dualpipeds.p4	\
		-DP4_NAME=dualpipeds								\
		-DP4_LANG=p4_16 									\
		-DTOFINO=ON
	
	make -C build/dualpipeds -j"$(nproc)" -l"$(nproc)" install

.CLEANUP:
	rm -rf build/dualpipe
	rm -rf build/dualpipeds