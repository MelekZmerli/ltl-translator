add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE utils helena dcr2cpn ltl2prop unfolder json cli11)

install(TARGETS ${PROJECT_NAME} DESTINATION ${INSTALL_FOLDER})