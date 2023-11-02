cmake_minimum_required(VERSION 3.25)

# project information
project(unfolding CXX)

# Third-party libraries
add_subdirectory(third-party)

# Source folder
add_subdirectory(src)

# The executable code
add_subdirectory(app)

# installation
install(TARGETS ${PROJECT_NAME} DESTINATION ${PROJECT_SOURCE_DIR}/bin)