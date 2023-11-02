# List of files
file(GLOB SOURCE_LIST CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

# Include header files
include_directories(../include)

# Create shared library
add_library(${PROJECT_NAME} STATIC ${SOURCE_LIST})
target_include_directories(${PROJECT_NAME} PUBLIC ../include)
target_link_libraries(${PROJECT_NAME} PRIVATE utils helena rapidxml)