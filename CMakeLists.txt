cmake_minimum_required(VERSION 3.13)

# Require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# installation folder
set(INSTALL_FOLDER ${CMAKE_SOURCE_DIR}/bin)

# project information
project(LTLTranslator CXX)

# Third-party libraries
add_subdirectory(third-party)

# Source folder
add_subdirectory(src)

# The executable code
add_subdirectory(app)

# documentation
add_subdirectory(docs)