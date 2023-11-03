include(FetchContent)
find_package(Doxygen)

if(NOT DOXYGEN_FOUND)
  add_custom_target(doxygen COMMAND false COMMENT "Doxygen not found")
  return()
endif()

# Download Doxygen theme: https://jothepro.github.io/doxygen-awesome-css/
FetchContent_Declare(doxygen-awesome-css
  GIT_REPOSITORY "https://github.com/jothepro/doxygen-awesome-css.git"
  GIT_TAG v2.2.1)
FetchContent_MakeAvailable(doxygen-awesome-css)

# Doxygen configuration
set(DOXYGEN_GENERATE_HTML YES)
set(DOXYGEN_GENERATE_TREEVIEW YES)
set(DISABLE_INDEX NO)
set(FULL_SIDEBAR NO)
set(HTML_COLORSTYLE LIGHT)
set(HAVE_DOT YES)
set(DOT_IMAGE_FORMAT svg)
set(DOT_TRANSPARENT YES)
set(DOXYGEN_HTML_EXTRA_STYLESHEET
  ${doxygen-awesome-css_SOURCE_DIR}/doxygen-awesome.css)
set(DOXYGEN_HTML_OUTPUT ${PROJECT_BINARY_DIR}/docs/html)

doxygen_add_docs(doxygen
  ${PROJECT_SOURCE_DIR}/src
  COMMENT "Generate HTML documenation")

# Copy documentation
install(DIRECTORY ${DOXYGEN_HTML_OUTPUT} DESTINATION ${INSTALL_FOLDER})
