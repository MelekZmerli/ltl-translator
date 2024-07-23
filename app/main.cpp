#include "LTLtranslator.hpp"
#include <CLI11.hpp>
#include <fstream>
#include <json.hpp>
#include <regex>
#include <map>
#include <memory>
#include <string>
#include <vector>


/**
 * Read a file from the filesystem
 *
 * @param filename path to the file to be read
 * @return string buffer
 */
  std::stringstream read_file(const std::string &filename) {
  std::string new_line;
  std::stringstream text_stream;
  std::ifstream file_stream(filename);

  while (std::getline(file_stream, new_line)) {
    text_stream << new_line << "\n";
  }

  return text_stream;
}

/**
 * Read a file and parse it into a JSON file
 *
 * @param filename path to the file to be read
 * @return deserialized json object
 */
nlohmann::json parse_json_file(const std::string &filename) {
  std::string content;
  std::string new_line;
  std::ifstream file_stream(filename);

  while (std::getline(file_stream, new_line)) {
    content += new_line + "\n";
  }

  return nlohmann::json::parse(content);
}

/**
 * Save a content into a file (overwrite)
 *
 * @param filename path to the output file
 * @param content string to the be saved
 */
void save_content(const std::string &filename, const std::string &content) {

      std::ofstream output_file(filename);
      output_file << content;
      output_file.close();  
}

void removeLastOccurrenceFromFile(const std::string& filename, char charToRemove) {
    std::ifstream inFile(filename);
    if (!inFile) {
        std::cerr << "Error: Could not open the file for reading!" << std::endl;
        return;
    }

    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    size_t pos = content.find_last_of(charToRemove);
    if (pos != std::string::npos) {
        content.erase(pos, 1);

        std::ofstream outFile(filename);
        if (!outFile) {
            std::cerr << "Error: Could not open the file for writing!" << std::endl;
            return;
        }
        outFile << content;
        outFile.close();
    }
}

/**
 * Append content to a file
 *
 * @param filename path to the output file
 * @param content string to the be saved
 */
void append_content(const std::string& filename, const std::string& content) {
    std::ofstream outFile;

    // Open file in append mode
    outFile.open(filename, std::ios_base::app);

    if (!outFile.is_open()) {
        std::cerr << "Error: Could not open the file!" << std::endl;
        return;
    }

    // Write content to file
    outFile  << content << '\n' << '}' << std::endl;

    // Close the file
    outFile.close();

    if (outFile.fail()) {
        std::cerr << "Error: Could not close the file properly!" << std::endl;
    }
}

int main(int argc, char **argv) {
  CLI::App app{"LTLTranslator tool"};

  std::string LTL_FILE_PATH;
  app.add_option("--ltl", LTL_FILE_PATH,
                 "LTL file (.json), Vulnerabilities to check")
      ->required()
      ->check(CLI::ExistingFile);

  std::string LNA_JSON_FILE_PATH;
  app.add_option("--lna-info", LNA_JSON_FILE_PATH,
                 "JSON file (.json), output of solidity2cpn tool")
      ->required()
      ->check(CLI::ExistingFile);

  std::string OUT_FILE_PATH;
  app.add_option("--output-path", OUT_FILE_PATH, "Output file path")
      ->default_val("./")
      ->check(CLI::ExistingDirectory);

  std::string OUT_FILE_NAME;
  app.add_option("--output-name", OUT_FILE_NAME, "Output file name")
      ->default_val("output");

  CLI11_PARSE(app, argc, argv);

  // full output path
  std::string full_outpath = OUT_FILE_PATH + OUT_FILE_NAME;

  /****************************************************************************
   * READ FILES
   ****************************************************************************/

  nlohmann::json ltl_json = parse_json_file(LTL_FILE_PATH);
  nlohmann::json sol_json = parse_json_file(LNA_JSON_FILE_PATH);

  LTL2PROP::LTLTranslator ltl_translator = LTL2PROP::LTLTranslator(sol_json, ltl_json);

  std::map<std::string, std::string> ltl_result = ltl_translator.translate();
  save_content(full_outpath + ".prop.lna", ltl_result["property"]);

  removeLastOccurrenceFromFile(full_outpath + "_HCPN.lna", '}');
  append_content(full_outpath + "_HCPN.lna", ltl_result["propositions"]);

  return 0;
}
