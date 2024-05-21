#include "LTLtranslator.hpp"

#include <stddef.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include "json.hpp"


namespace LTL2PROP {

  LTLTranslator::LTLTranslator(const nlohmann::json& lna_json,
                              const nlohmann::json& ltl_json) {
    formula_json = ltl_json;
    handleVariable(lna_json);
  }

  LTLTranslator::vulnerabilities LTLTranslator::getVulnerability(std::string vulnerability){
    if (vulnerability == "Integer Overflow/Underflow") return IntegerOverflowUnderflow;
    if (vulnerability == "Timestamp Dependance") return TimestampDependence;
    if (vulnerability == "Reentrancy") return Reentrancy;
    if (vulnerability == "Skip Empty String Literal") return SkipEmptyStringLiteral;
    if (vulnerability == "Uninitialized Storage Variable") return UninitializedStorageVariable;
    if (vulnerability == "Self Destruction") return SelfDestruction;
    }

  void LTLTranslator::handleVariable(const nlohmann::json& lna_json) {
    // get global variables
    for (const auto& global_var : lna_json.at("globalVariables")) {
      global_variables[global_var.at("name")] = global_var.at("placeType");
    }

    // get local variables from functions
    for (const auto& function : lna_json.at("functions")) {
      for (const auto& local_var : function.at("localVariables")) {
        local_variables[local_var.at("name")] = local_var.at("place");
      }
    }

    statements = lna_json.at("statements");
    // get assignments
    for (const auto& assignment : statements.at("assignments")) {
      assignments[assignment.at("output_place")] = assignment.at("variable");
    }

    // get sendings
    for (const auto& sending : statements.at("sendings")) {
      sendings[sending.at("output_place")] = sending.at("variable");
    }

    // get function calls
    for (const auto& function_call : statements.at("function_call")) {
      function_calls[function_call.at("output_place")] = function_call.at("function_name");
    }

    // get branchings
    for (const auto& branching : statements.at("branching")) {
      function_calls[branching.at("output_place")] = branching.at("variable");
    }
  }

  bool LTLTranslator::is_global_variable(const std::string& _name) const {
    return global_variables.find(_name) != global_variables.end();
  }

  std::string LTLTranslator::get_global_variable_placetype(
      const std::string& _name) {
    return is_global_variable(_name) ? global_variables[_name] : "";
  }

  bool LTLTranslator::is_local_variable(const std::string& _name) const {
    return local_variables.find(_name) != local_variables.end();
  }

  std::string LTLTranslator::get_local_variable_placetype(
      const std::string& _name) {
    return is_local_variable(_name) ? local_variables[_name] : "";
  }

  std::map<std::string, std::string> LTLTranslator::translate() {
    // get the type of formula : general or specific
    std::string formula_type = formula_json.at("type");
    auto formula_params = formula_json.at("params");
    std::string vulnerability_name = formula_params.at("name");
    nlohmann::json inputs = formula_params.at("inputs");

    // parse a general vulnerability formula
    if (formula_type == "general") {


      switch(LTLTranslator::getVulnerability(vulnerability_name)){
        case(IntegerOverflowUnderflow):
          return detectUnderOverFlowVul(inputs);
        case(SelfDestruction):
          return detectSelfDestruction(inputs);
        case(Reentrancy):
          // return detectReentrancy(inputs);
        case(TimestampDependence):
          // return detectTimestampDependance(inputs);
        case(SkipEmptyStringLiteral):
          // return detectSkipEmptyStringLiteral(inputs);
        case(UninitializedStorageVariable):
          // return detectUninitializedStorageVariable(inputs);
        case(AlwaysLessThan):
          return checkAlwaysLessThan(inputs); // TODO: add variable 2 case
        case(AlwaysMoreThan):
          return checkAlwaysLessThan(inputs); // TODO: add variable 2 case
        case(IsConstant):
          return checkIsConstant(inputs); // TODO: add variable 2 case
      }
    }

    // throw an exception since the type cannot be handled
    throw std::runtime_error("formula type " + vulnerability_name + " is not handled by LTLTranslator");
  }
  std::map<std::string, std::string> LTLTranslator::detectSelfDestruction(nlohmann::json inputs) {
    // First Formula 
    if (inputs.at("rival_contract").empty()){
      std::string output_place;
      for (const auto& branching : sendings) {
        if (branching.second == inputs.at("selected_variable")){
          output_place = branching.first;
          break;
        }
      }      
    
      result["property"] = "ltl property selfdestruction: not testonbalance";
      result["proposition"] = "proposition testonbalance:  "+ output_place +"'card > 0";
    }
    // Second Formula
    else{
      
      result["property"] = "ltl property selfdestruction: (not testonbalance) or (not selfdestruct until start)";
      result["propositions"] = "proposition testonbalance: branching_statement_output(balance)'card > 0 \
                                proposition selfdestruct: function_call_statement_output(seldfdestruct)'card > 0 \
                                proposition start: ??????";
    }
  }

  std::map<std::string, std::string> LTLTranslator::detectUnderOverFlowVul(nlohmann::json inputs) {
    std::string min_threshold = inputs.at("min_threshold");
    std::string max_threshold = inputs.at("max_threshold");
    std::string variable = inputs.at("selected_variable");
    result["property"] = "ltl property outOfRange: [] ( not OUFlow ) ;";
    if (is_global_variable(variable)) {
      result["propositions"] = "proposition OUFlow: exists (t in S | (t->1)." + variable + " < " + min_threshold +") or exists (t in S | (t->1)." + variable + " > " + max_threshold + ");";
    
    }
    else
    {
      std::string variable_place = local_variables[variable];

      result["propositions"] = "proposition OUFlow: exists (t in "+ variable_place + " | (t->1)." + variable + " < " + min_threshold +") or exists (t in "+ variable_place \
      +" | (t->1)." + variable + " > " + max_threshold + ");";
    }
    std::cout << result["propositions"]<< std::endl;
    std::cout << result["property"];
    return result;

  }

  std::map<std::string, std::string> detectSkipEmptyStringLiteral(nlohmann::json inputs){
      std::string function = inputs.at("selected_function");
      result["property"] = "ltl property skipempty: [] not emptyparam;";
      result["propositions"] = "exists (t in " + function + "_PAR | ((t->1)'space > 0) and ((t->1)'last'card > 0));";
  }


  std::map<std::string, std::string> LTLTranslator::checkAlwaysLessThan(nlohmann::json inputs){
    std::string max_threshold = inputs.at("constant");
    std::string variable = inputs.at("selected_variable");
    result["property"] = "ltl property smaller: [] not more;";

    if (is_global_variable(variable)) {
      result["propositions"] = "proposition more: exists (t in S | (t->1)." + variable + " > " + max_threshold +");";
    }
    else
    {
      std::string variable_place = local_variables[variable];
      result["propositions"] = "proposition more: exists (t in "+ variable_place + " | (t->1)." + variable + " > " + max_threshold +");";
    }
  }


  std::map<std::string, std::string> LTLTranslator::checkAlwaysMoreThan(nlohmann::json inputs){
    std::string min_threshold = inputs.at("constant");
    std::string variable = inputs.at("selected_variable");
    result["property"] = "ltl property bigger: [] not less;";

    if (is_global_variable(variable)) {
      result["propositions"] = "proposition less: exists (t in S | (t->1)." + variable + " < " + min_threshold +");";
    }
    else
    {
      std::string variable_place = local_variables[variable];
      result["propositions"] = "proposition less: exists (t in "+ variable_place + " | (t->1)." + variable + " < " + min_threshold +");";
    }
  }

  std::map<std::string, std::string> LTLTranslator::checkIsConstant(nlohmann::json inputs) {
    std::string constant = inputs.at("constant");
    std::string variable = inputs.at("selected_variable");
    result["property"] = "ltl property equals: [] not different;";

    if (is_global_variable(variable)) {
      result["propositions"] = "proposition different: exists (t in S | (t->1)." + variable + " != " + constant +");";
    }
    else
    {
      std::string variable_place = local_variables[variable];
      result["propositions"] = "proposition different: exists (t in "+ variable_place + " | (t->1)." + variable + " != " + constant +");";
    }
  }
}  // namespace LTL2PROP