# CMake generated Testfile for 
# Source directory: C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests
# Build directory: C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(compress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Debug/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.bz2")
  set_tests_properties(compress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(compress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Release/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.bz2")
  set_tests_properties(compress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(compress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/MinSizeRel/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.bz2")
  set_tests_properties(compress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(compress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/RelWithDebInfo/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.bz2")
  set_tests_properties(compress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
else()
  add_test(compress_sample1.ref NOT_AVAILABLE)
endif()
if("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(compress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Debug/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.bz2")
  set_tests_properties(compress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(compress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Release/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.bz2")
  set_tests_properties(compress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(compress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/MinSizeRel/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.bz2")
  set_tests_properties(compress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(compress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/RelWithDebInfo/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.bz2")
  set_tests_properties(compress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
else()
  add_test(compress_sample2.ref NOT_AVAILABLE)
endif()
if("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(compress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Debug/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.bz2")
  set_tests_properties(compress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(compress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Release/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.bz2")
  set_tests_properties(compress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(compress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/MinSizeRel/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.bz2")
  set_tests_properties(compress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(compress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "compress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/RelWithDebInfo/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.bz2")
  set_tests_properties(compress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;20;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
else()
  add_test(compress_sample3.ref NOT_AVAILABLE)
endif()
if("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(decompress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Debug/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref")
  set_tests_properties(decompress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(decompress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Release/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref")
  set_tests_properties(decompress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(decompress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/MinSizeRel/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref")
  set_tests_properties(decompress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(decompress_sample1.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/RelWithDebInfo/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample1.ref")
  set_tests_properties(decompress_sample1.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
else()
  add_test(decompress_sample1.ref NOT_AVAILABLE)
endif()
if("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(decompress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Debug/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref")
  set_tests_properties(decompress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(decompress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Release/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref")
  set_tests_properties(decompress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(decompress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/MinSizeRel/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref")
  set_tests_properties(decompress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(decompress_sample2.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/RelWithDebInfo/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample2.ref")
  set_tests_properties(decompress_sample2.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
else()
  add_test(decompress_sample2.ref NOT_AVAILABLE)
endif()
if("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(decompress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Debug/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref")
  set_tests_properties(decompress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(decompress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/Release/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref")
  set_tests_properties(decompress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(decompress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/MinSizeRel/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref")
  set_tests_properties(decompress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
elseif("${CTEST_CONFIGURATION_TYPE}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(decompress_sample3.ref "C:/Users/Admin/AppData/Local/Programs/Python/Python310/python.exe" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/runtest.py" "--mode" "decompress" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/build/RelWithDebInfo/bzip2.exe" "-1" "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/sample3.ref")
  set_tests_properties(decompress_sample3.ref PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;39;add_test;C:/Users/Admin/Desktop/dev/CryptoZ/deps/bzip2/tests/CMakeLists.txt;0;")
else()
  add_test(decompress_sample3.ref NOT_AVAILABLE)
endif()