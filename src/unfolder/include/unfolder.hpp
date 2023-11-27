#ifndef UNFOLDER_H_
#define UNFOLDER_H_

#include <json.hpp>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "Helena.hpp"
#include "LTLtranslator.hpp"

class Unfolder {
 public:
  /**
   * Construct a new unfolder object
   *
   * @param _context pointer to the behavioral context
   * @param _sol_lna_stream CPN model of the solidity code
   * @param lna_json information of the CPN model
   * @param ltl_json LTL formula to be verified
   * @param im_json initial marking
   */
  Unfolder(const HELENA::StructuredNetNodePtr& _context,
           std::stringstream& _sol_lna_stream, const nlohmann::json& lna_json,
           const nlohmann::json& ltl_json, const nlohmann::json& im_json);

  std::vector<std::string> FindUnfoldedFunction();

  void initialMarkingSetting();

  static HELENA::StructuredNetNodePtr analyseLnaFile(
      std::stringstream& _sol_lna_stream);

  HELENA::StructuredNetNodePtr unfoldModelWithDCRContext();
  HELENA::StructuredNetNodePtr unfoldModelWithFreeContext();

  std::map<std::string, std::string> UnfoldModel(const std::string& _context);

  std::string get_model_name_from_comment(
      const HELENA::CommentNodePtr& _comment);

 private:
  nlohmann::json sol_information;
  nlohmann::json ltl_information;
  nlohmann::json im_information;

  std::vector<std::string> unfolded_func;
  HELENA::StructuredNetNodePtr cpn_model;
  HELENA::StructuredNetNodePtr cpn_context;
};

#endif