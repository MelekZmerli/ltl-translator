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
    for (const auto& global_var : lna_json.at("global_variables")) {
      global_variables.push_back(global_var.at("name"));
    }

    // get local variables from functions
    for (const auto& function : lna_json.at("functions")) {
      for (const auto& local_var : function.at("local_variables")) {
        local_variables[local_var.at("name")] = local_var.at("place");
      }
    }

    statements = lna_json.at("statements");
    // get assignments
    for (const auto& assignment : statements.at("assignment")) {
      assignments[assignment.at("output_place")].variable = assignment.at("variable");
      assignments[assignment.at("output_place")].parent = assignment.at("parent");
      assignments[assignment.at("output_place")].RHV = assignment["right_hand_variables"].get<std::list<std::string>>();
      assignments[assignment.at("output_place")].timestamp = assignment.at("timestamp");

    }

    // get sendings
    for (const auto& sending : statements.at("sending")) {
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
    return (std::find(global_variables.begin(), global_variables.end(), _name) != global_variables.end());
  }

  bool LTLTranslator::is_local_variable(const std::string& _name) const {
    return local_variables.find(_name) != local_variables.end();
  }

  std::string LTLTranslator::get_local_variable_placetype(
      const std::string& _name) {
    return is_local_variable(_name) ? local_variables[_name] : "";
  }

  std::string LTLTranslator::get_sending_output_place(std::string variable){
    for (const auto& sending: sendings) {
      if (sending.second == variable){
          return sending.first;
        }
      }      
  }

  std::string LTLTranslator::get_assignment_output_place(std::string variable){
    for (const auto& assignment: assignments) {
      if (assignment.second.variable == variable){
          return assignment.first;
        }
      }      
  }

  std::string LTLTranslator::get_branching_output_place(std::string variable){
    for (const auto& branching: branchings) {
      if (branching.second == variable){
          return branching.first;
        }
      }      
  }

  std::string LTLTranslator::get_function_call_output_place(std::string function_name){
    for (const auto& function_call: function_calls) {
      if (function_call.second == function_name){
          return function_call.first;
        }
      }     
  }

  std::string LTLTranslator::get_timestamp_output_place(){
    for (const auto& assignment: assignments) {
      if (assignment.second.timestamp){
        return assignment.first;
      }
    }
    return "";     
  }

  bool LTLTranslator::timestamp_exists(){
    for (const auto& assignment: assignments) {
      if (assignment.second.timestamp){
        return true;
      }
    }
    return false;     

  }

  std::string LTLTranslator::get_read_output_place(std::string variable){
    for (const auto& assignment: assignments) {
      for (const auto& RHVariable: assignment.second.RHV){
        if (RHVariable == variable){
          return assignment.first;
        } 
      }
    }
    return "";     
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
          return detectReentrancy(inputs);
        case(TimestampDependence):
          return detectTimestampDependance(inputs);
        case(SkipEmptyStringLiteral):
          return detectSkipEmptyStringLiteral(inputs);
        case(UninitializedStorageVariable):
          return detectUninitializedStorageVariable(inputs);
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
    std::string branching_output_place = get_branching_output_place(inputs.at("selected_variable"));

    // First Formula 
    if (inputs.at("rival_contract").empty()){
      result["property"] = "ltl property selfdestruction: not testonbalance";
      result["proposition"] = "proposition testonbalance:  "+ branching_output_place +"'card > 0;";
    }
    // Second Formula
    else{
      std::string function_call_output_place = get_function_call_output_place("selfdestruct");

      result["property"] = "ltl property selfdestruction: (not testonbalance) or (not selfdestruct until start)";
      result["propositions"] = "proposition testonbalance:"+ branching_output_place +"'card > 0; \
                                proposition selfdestruct:"+ function_call_output_place +"'card > 0; \
                                proposition start: ??????;"; // TODO: start proposition
    }
    return result;
  }

  std::map<std::string, std::string> LTLTranslator::detectReentrancy(nlohmann::json inputs) {
    std::string sending_output_place = get_sending_output_place(inputs.at("selected_variable"));
    // First version
    if(inputs.at("rival_contract").empty()){
      std::string assignment_output_place = get_assignment_output_place(inputs.at("selected_variable"));

      result["property"] = "ltl property reentrancy1: [] ( not ( not assignment until sending) );";
      result["propositions"] = "proposition assignment: (" + assignment_output_place +"’card > 0) \
      proposition sending: ("+ sending_output_place +"’card > 0)";
    }
    // Second version
    // TODO: find alternative to X operator 
    else {
      std::string fallback_output_place = get_function_call_output_place("fallback");
      result["property"] = "ltl property reentrancy2: sending => X [] (( not sending) until end_fallback);";
      result["propositions"] = "proposition sending: "+ sending_output_place +"'card > 0 \
                                proposition end_fallback: " + fallback_output_place + "'card > 0";
    }
    return result;
  }

  std::map<std::string, std::string> LTLTranslator::detectTimestampDependance(nlohmann::json inputs) {
    if(timestamp_exists()){
      std::string timestamp_place = get_timestamp_output_place();
      result["property"] = "ltl property tsindependant: [] not timestampstatement;";
      result["propositions"] = "property timestampstatement: "+ timestamp_place +"'card > 0";
    }
    else {
      result["property"] = "ltl property tsindependant: true;";
    }
    
    return result;
  }

  std::map<std::string, std::string> LTLTranslator::detectUninitializedStorageVariable(nlohmann::json inputs) {
    std::string write_output_place = get_assignment_output_place(inputs.at("selected_variable"));
    std::string read_output_place = get_read_output_place(inputs.at("selected_variable"));

    result["property"] = "ltl property usv: not read until write;";
    result["propostions"] = "proposition read: exists(t in " + read_output_place + ") | (t->1).X'card > 0) \
                             proposition write: exists(t in " + write_output_place +" | (t->1).X'card > 0)";
  }

  std::map<std::string, std::string> LTLTranslator::detectUnderOverFlowVul(nlohmann::json inputs) {
    std::string min_threshold = inputs.at("min_threshold");
    std::string max_threshold = inputs.at("max_threshold");
    std::string variable = inputs.at("selected_variable");
    std::cout << result["propositions"]<< std::endl;
    std::cout << result["property"] << std::endl; 
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

  std::map<std::string, std::string> LTLTranslator::detectSkipEmptyStringLiteral(nlohmann::json inputs){
      std::string function = inputs.at("selected_function");
      result["property"] = "ltl property skipempty: [] not emptyparam;";
      result["propositions"] = "exists (t in " + function + "_PAR | ((t->1)'space > 0) and ((t->1)'last'card > 0));";
      return result;

  }


  std::map<std::string, std::string> LTLTranslator::checkAlwaysLessThan(nlohmann::json inputs){
    std::string variable = inputs.at("selected_variable");
    result["property"] = "ltl property smaller: [] not more;";

    if(inputs.at("rival_variable").empty()){
      std::string max_threshold = inputs.at("constant");
      if (is_global_variable(variable)) {
        result["propositions"] = "proposition more: exists (t in S | (t->1)." + variable + " > " + max_threshold +");";
      }
      else
      {
        std::string variable_place = local_variables[variable];
        result["propositions"] = "proposition more: exists (t in "+ variable_place + " | (t->1)." + variable + " > " + max_threshold +");";
      }
    }
    else {
      std::string rival_variable = inputs.at("rival_variable");
      if (is_global_variable(variable) && is_global_variable(rival_variable)) {
        result["propositions"] = "proposition more: exists (t in S | (t->1)." + variable + " > (t->1)." + rival_variable +");";
      }
      else if(is_global_variable(variable)) {
        std::string rival_variable_place = local_variables[rival_variable];
        result["propositions"] = "proposition more: exists (t in S, t2 in "+ rival_variable_place + " | (t->1)." + variable + " > (t2->1)." + rival_variable +");";
      }
      else if(is_global_variable(rival_variable)) {
        std::string variable_place = local_variables[variable];
        result["propositions"] = "proposition more: exists (t in "+ variable_place + ", t2 in S | (t->1)." + variable + " > (t2->1)." + rival_variable +");";
      }
      else {
        std::string variable_place = local_variables[variable];
        std::string rival_variable_place = local_variables[rival_variable];
        result["propositions"] = "proposition more: exists (t in "+ variable_place + ", t2 in "+ rival_variable_place +" | (t->1)." + variable + " > (t2->1)." + rival_variable +");";
      }   
    }  
    return result;
  }


  std::map<std::string, std::string> LTLTranslator::checkAlwaysMoreThan(nlohmann::json inputs){
    result["property"] = "ltl property bigger: [] not less;";
    std::string variable = inputs.at("selected_variable");
    
    if(inputs.at("rival_variable").empty()){
      std::string min_threshold = inputs.at("constant");
      if (is_global_variable(variable)) {
        result["propositions"] = "proposition less: exists (t in S | (t->1)." + variable + " < " + min_threshold +");";
      }
      else
      {
        std::string variable_place = local_variables[variable];
        result["propositions"] = "proposition less: exists (t in "+ variable_place + " | (t->1)." + variable + " < " + min_threshold +");";
      }
    }
    else {
      std::string rival_variable = inputs.at("rival_variable");
      if (is_global_variable(variable) && is_global_variable(rival_variable)) {
        result["propositions"] = "proposition less: exists (t in S | (t->1)." + variable + " < (t->1)." + rival_variable +");";
      }
      else if(is_global_variable(variable)) {
        std::string rival_variable_place = local_variables[rival_variable];
        result["propositions"] = "proposition less: exists (t in S, t2 in "+ rival_variable_place + " | (t->1)." + variable + " < (t2->1)." + rival_variable +");";
      }
      else if(is_global_variable(rival_variable)) {
        std::string variable_place = local_variables[variable];
        result["propositions"] = "proposition less: exists (t in "+ variable_place + ", t2 in S | (t->1)." + variable + " < (t2->1)." + rival_variable +");";
      }
      else {
        std::string variable_place = local_variables[variable];
        std::string rival_variable_place = local_variables[rival_variable];
        result["propositions"] = "proposition less: exists (t in "+ variable_place + ", t2 in "+ rival_variable_place +" | (t->1)." + variable + " < (t2->1)." + rival_variable +");";
      }   
    }  
    return result;
  }

  std::map<std::string, std::string> LTLTranslator::checkIsConstant(nlohmann::json inputs) {
    std::string variable = inputs.at("selected_variable");
    result["property"] = "ltl property equals: [] not different;";
    
    if(inputs.at("rival_variable").empty()){
      std::string constant = inputs.at("constant");
      if (is_global_variable(variable)) {
        result["propositions"] = "proposition different: exists (t in S | (t->1)." + variable + " != " + constant +");";
      }
      else
      {
        std::string variable_place = local_variables[variable];
        result["propositions"] = "proposition different: exists (t in "+ variable_place + " | (t->1)." + variable + " != " + constant +");";
      }
    }
    else {
      std::string rival_variable = inputs.at("rival_variable");
      if (is_global_variable(variable) && is_global_variable(rival_variable)) {
        result["propositions"] = "proposition different: exists (t in S | (t->1)." + variable + " != (t->1)." + rival_variable +");";
      }
      else if(is_global_variable(variable)) {
        std::string rival_variable_place = local_variables[rival_variable];
        result["propositions"] = "proposition different: exists (t in S, t2 in "+ rival_variable_place + " | (t->1)." + variable + " != (t2->1)." + rival_variable +");";
      }
      else if(is_global_variable(rival_variable)) {
        std::string variable_place = local_variables[variable];
        result["propositions"] = "proposition different: exists (t in "+ variable_place + ", t2 in S | (t->1)." + variable + " != (t2->1)." + rival_variable +");";
      }
      else {
        std::string variable_place = local_variables[variable];
        std::string rival_variable_place = local_variables[rival_variable];
        result["propositions"] = "proposition different: exists (t in "+ variable_place + ", t2 in "+ rival_variable_place +" | (t->1)." + variable + " != (t2->1)." + rival_variable +");";
      }   
    }
    return result;  
  }
}  // namespace LTL2PROP