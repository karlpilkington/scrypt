cmake_minimum_required (VERSION 2.6)
project (scrypt)

include (CheckIncludeFile)
check_include_file (inttypes.h HAVE_INTTYPES_H)
check_include_file (stdint.h HAVE_STDINT_H)

include (TestBigEndian)
test_big_endian (WORDS_BIGENDIAN)

configure_file (
	"${PROJECT_SOURCE_DIR}/config.h.in"
	"${PROJECT_BINARY_DIR}/config.h"
	)

include_directories ("${PROJECT_BINARY_DIR}")
add_definitions (-DHAVE_CONFIG_H -DSCRYPT_TEST)

add_executable (test scrypt.c pbkdf2-hmac-sha256.c hmac-sha256.c sha256.c)
