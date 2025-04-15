cmake_minimum_required (VERSION 3.5)
project (optee_test C)

# Default cross compile settings
set (CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)

option(CFG_WERROR "Build with -Werror" FALSE)

set (OPTEE_TEST_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
################################################################################
# Compiler flags:
#   We want to use the same flags in the entire optee_client git
################################################################################
add_compile_options (
	-Wall -Wbad-function-cast -Wcast-align
	-Werror-implicit-function-declaration -Wextra
	-Wfloat-equal -Wformat-nonliteral -Wformat-security
	-Wformat=2 -Winit-self -Wmissing-declarations
	-Wmissing-format-attribute -Wmissing-include-dirs
	-Wmissing-prototypes -Wnested-externs
	-Wpointer-arith -Wshadow -Wstrict-prototypes
	-Wswitch-default -Wunsafe-loop-optimizations
	-Wwrite-strings -fPIC
 	-Wno-missing-field-initializers
	-Wno-unused-parameter -Wno-alloc-size
)
if(CFG_WERROR)
    add_compile_options(-Werror)
endif(CFG_WERROR)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

add_subdirectory (ta)
add_subdirectory (host/xtest)
add_subdirectory (host/supp_plugin)
