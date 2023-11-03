#include <CLI11.hpp>
#include <fstream>
#include <iostream>
#include <json.hpp>
#include <list>
#include <sstream>
#include <string>
#include <vector>

#include "DCR.hpp"
#include "Helena.hpp"
#include "dcr2cpn.hpp"
#include "unfolder.hpp"

stringstream read_file(std::string filename) {
  std::string new_line;
  stringstream text_stream;
  ifstream file_stream(filename);

  while (getline(file_stream, new_line)) {
    text_stream << new_line << "\n";
  }

  return text_stream;
}

nlohmann::json parse_json_file(std::string filename) {
  string content;
  std::string new_line;
  ifstream file_stream(filename);

  while (getline(file_stream, new_line)) {
    content = content + new_line + "\n";
  }

  return nlohmann::json::parse(content);
}

int main(int argc, char** argv) {
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
      ->default_val(".")
      ->check(CLI::ExistingFile);

  string OUT_FILE_NAME;
  app.add_option("--output_name", OUT_FILE_NAME, "Output file name")
      ->default_val("output");

  CLI11_PARSE(app, argc, argv);

  /**
   * Process .lna file
   */
  stringstream model_lna_text_stream = read_file(MODEL_LNA_FILE_PATH);
  stringstream ast_text_stream = read_file(AST_FILE_PATH);

  nlohmann::json ltl_json = parse_json_file(LTL_FILE_PATH);
  nlohmann::json sol_json = parse_json_file(LNA_JSON_FILE_PATH);
  nlohmann::json im_json = parse_json_file(IM_JSON_FILE_PATH);

  /**
   * name
   */
  std::string outfile_name;
  if (OUT_FILE_NAME.compare("") == 0) {
    std::vector<std::string> t = split(MODEL_LNA_FILE_PATH, "/");
    outfile_name = split_ex(t[t.size() - 1], ".", 2)[0];
  } else {
    outfile_name = OUT_FILE_NAME;
  }

  std::string outfile_path;
  if (OUT_FILE_NAME.compare("") == 0) {
    outfile_path = "./";
  } else {
    outfile_path = OUT_FILE_PATH;
  }

  std::string full_outpath = outfile_path + outfile_name;

  /**
   * run
   */
  StructuredNetNodePtr context_net;
  if (CONTEXT_TYPE == "DCR") {
    DCR2CPN::DCRClass dcrClass = DCR2CPN::readDCRFromXML(CONTEXT_FILE_PATH);
    DCR2CPN::Dcr2CpnTranslator contextTranslator =
        DCR2CPN::Dcr2CpnTranslator(dcrClass);
    context_net = contextTranslator.translate();
  } else if (CONTEXT_TYPE == "CPN") {
    stringstream context_text_stream = read_file(CONTEXT_FILE_PATH);
    context_net = Unfolder::analyseLnaFile(context_text_stream);
  } else if (CONTEXT_TYPE == "FREE") {
    context_net = std::make_shared<StructuredNetNode>();
  } else {
    context_net = std::make_shared<StructuredNetNode>();
  }

  ofstream context_file;
  context_file.open(full_outpath + ".context.lna");
  context_file << context_net->source_code();
  context_file.close();

  Unfolder unfolder =
      Unfolder(context_net, model_lna_text_stream, sol_json, ltl_json, im_json);
  std::map<std::string, std::string> unfold_model =
      unfolder.UnfoldModel(CONTEXT_TYPE);

  ofstream lna_file;
  lna_file.open(full_outpath + ".lna");
  lna_file << unfold_model["lna"];
  lna_file.close();

  ofstream prop_file;
  prop_file.open(full_outpath + ".prop.lna");
  prop_file << unfold_model["prop"];
  prop_file.close();

  return 0;
}
