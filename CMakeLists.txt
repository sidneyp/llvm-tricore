cmake_minimum_required(VERSION 2.8.8)

project(tricore-llvm)

find_package(LLVM REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using Tablegen in: ${LLVM_TOOLS_BINARY_DIR}")
message(STATUS "Using Inc Directories in: ${LLVM_INCLUDE_DIRS}")

find_program(LLVM_TABLEGEN_EXE "llvm-tblgen" ${LLVM_TOOLS_BINARY_DIR} NO_DEFAULT_PATH)

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

set(LLVM_MAIN_SRC_DIR ${LLVM_DIR} CACHE PATH "Path to LLVM source tree")
set(LLVM_MAIN_INCLUDE_DIR ${LLVM_DIR}/llvm CACHE PATH "Path to LLVM/include/llvm source tree")

include(AddLLVM)
include(TableGen)
include(HandleLLVMOptions)

add_subdirectory(TriCore)
