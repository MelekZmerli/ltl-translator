#ifndef UNFOLDER_H_
#define UNFOLDER_H_

#include <cctype>
#include <iostream>
#include <json.hpp>
#include <list>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "Helena.hpp"
#include "LNAAnalyser.hpp"
#include "LTLtranslator.hpp"
#include "utils.hpp"

using namespace HELENA;
using namespace LTL2PROP;

class Unfolder {
 public:
  Unfolder(const StructuredNetNodePtr& _context,
           std::stringstream& _sol_lna_stream, const nlohmann::json& lna_json,
           const nlohmann::json& ltl_json, const nlohmann::json& im_json);

  std::vector<std::string> FindUnfoldedFunction();

  void initialMarkingSetting();

  static StructuredNetNodePtr analyseLnaFile(
      std::stringstream& _sol_lna_stream);

  StructuredNetNodePtr unfoldModelWithDCRContext();
  StructuredNetNodePtr unfoldModelWithFreeContext();

  std::map<std::string, std::string> UnfoldModel(const std::string& _context);

  std::string get_model_name_from_comment(const CommentNodePtr& _comment);

 private:
  nlohmann::json sol_information;
  nlohmann::json ltl_information;
  nlohmann::json im_information;

  std::vector<std::string> unfolded_func;
  StructuredNetNodePtr cpn_model;
  StructuredNetNodePtr cpn_context;
};

#endif