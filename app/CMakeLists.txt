add_executable(${PROJECT_NAME} unfolding.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE dcr2cpn helena unfolder json cli11)