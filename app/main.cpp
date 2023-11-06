#include <CLI11.hpp>
#include <fstream>
#include <json.hpp>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "DCR.hpp"
#include "Helena.hpp"
#include "dcr2cpn.hpp"
#include "unfolder.hpp"

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
    content = content + new_line + "\n";
  }

  return nlohmann::json::parse(content);
}

/**
 * Save a content into a file
 *
 * @param filename path to the output file
 * @param content string to the be saved
 */
void save_content(const std::string &filename, const std::string &content) {
  std::ofstream output_file;
  output_file.open(filename);
  output_file << content;
  output_file.close();
}

int main(int argc, char **argv) {
  CLI::App app{"Unfolding tool"};

  std::string MODEL_LNA_FILE_PATH;
  app.add_option("--lna", MODEL_LNA_FILE_PATH,
                 "LNA file (.lna), output of solidity2cpn tool")
      ->required()
      ->check(CLI::ExistingFile);

  std::string CONTEXT_FILE_PATH;
  app.add_option("--context", CONTEXT_FILE_PATH,
                 "CONTEXT file (.xml), context of model")
      ->required()
      ->check(CLI::ExistingFile);

  string CONTEXT_TYPE;
  app.add_option("--context-type", CONTEXT_TYPE, "Context type")
      ->check(CLI::IsMember({"DCR", "CPN", "FREE"}))
      ->required();

  string LTL_FILE_PATH;
  app.add_option("--ltl", LTL_FILE_PATH,
                 "LTL file (.json), Vulnerabilities to check")
      ->required()
      ->check(CLI::ExistingFile);

  string AST_FILE_PATH;
  app.add_option(
         "--sol-ast", AST_FILE_PATH,
         "AST file (.ast), output of solidity compiler in mode --ast-json")
      ->required()
      ->check(CLI::ExistingFile);

  string LNA_JSON_FILE_PATH;
  app.add_option("--lna-json", LNA_JSON_FILE_PATH,
                 "JSON file (.json), output of solidity2cpn tool")
      ->required()
      ->check(CLI::ExistingFile);

  string IM_JSON_FILE_PATH;
  app.add_option("--im-json", IM_JSON_FILE_PATH,
                 "JSON file (.json), initial marking settings")
      ->required()
      ->check(CLI::ExistingFile);

  string OUT_FILE_PATH;
  app.add_option("--output_path", OUT_FILE_PATH, "Output file path")
      ->default_val("./")
      ->check(CLI::ExistingFile);

  string OUT_FILE_NAME;
  app.add_option("--output_name", OUT_FILE_NAME, "Output file name")
      ->default_val("output");

  CLI11_PARSE(app, argc, argv);

  // full output path
  std::string full_outpath = OUT_FILE_PATH + OUT_FILE_NAME;

  /****************************************************************************
   * READ FILES
   ****************************************************************************/
  stringstream model_lna_text_stream = read_file(MODEL_LNA_FILE_PATH);
  stringstream ast_text_stream = read_file(AST_FILE_PATH);

  nlohmann::json ltl_json = parse_json_file(LTL_FILE_PATH);
  nlohmann::json sol_json = parse_json_file(LNA_JSON_FILE_PATH);
  nlohmann::json im_json = parse_json_file(IM_JSON_FILE_PATH);

  /****************************************************************************
   * PROCESS CONTEXT
   ****************************************************************************/
  HELENA::StructuredNetNodePtr context_net;
  if (CONTEXT_TYPE == "DCR") {
    DCR2CPN::DCRClass dcrClass = DCR2CPN::readDCRFromXML(CONTEXT_FILE_PATH);
    DCR2CPN::Dcr2CpnTranslator contextTranslator =
        DCR2CPN::Dcr2CpnTranslator(dcrClass);
    context_net = contextTranslator.translate();
  } else if (CONTEXT_TYPE == "CPN") {
    stringstream context_text_stream = read_file(CONTEXT_FILE_PATH);
    context_net = Unfolder::analyseLnaFile(context_text_stream);
  } else {
    // free context by default
    context_net = std::make_shared<StructuredNetNode>();
  }

  save_content(full_outpath + ".context.lna", context_net->source_code());

  /****************************************************************************
   * UNFOLD CPN MODEL AND PROPERTY
   ****************************************************************************/
  Unfolder unfolder =
      Unfolder(context_net, model_lna_text_stream, sol_json, ltl_json, im_json);
  std::map<std::string, std::string> unfold_model =
      unfolder.UnfoldModel(CONTEXT_TYPE);

  save_content(full_outpath + ".lna", unfold_model["lna"]);
  save_content(full_outpath + ".prop.lna", unfold_model["prop"]);

  return 0;
}
