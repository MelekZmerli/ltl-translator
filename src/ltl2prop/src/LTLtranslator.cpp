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
    if (vulnerability == "Always Less Than") return AlwaysLessThan;
    if (vulnerability == "Always More Than") return AlwaysMoreThan;
    if (vulnerability == "Always Equal") return AlwaysEqual;
    if (vulnerability == "Is Called") return IsCalled;
    if (vulnerability == "Is Never Called") return IsNeverCalled;
    if (vulnerability == "Is Executed") return IsExecuted;
    if (vulnerability == "Is Never Executed") return IsNeverExecuted;
    if (vulnerability == "Sequential Call") return SequentialCall;
    if (vulnerability == "Infinite Loop") return InfiniteLoop;
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
      AssignmentStatement as = {
        .variable = assignment.at("variable"),
        .input_place = assignment.at("input_place"),
        .parent = assignment.at("parent"),
        .output_place = assignment.at("output_place"),
        .RHV = assignment["right_hand_variables"].get<std::list<std::string>>(),
        .timestamp = assignment.at("timestamp"),
      };
      assignments.push_back(as);
    }

    // get sendings
    for (const auto& sending : statements.at("sending")) {
            SendingStatement ss = {
        .variable = sending.at("variable"),
        .input_place = sending.at("input_place"),
        .parent = sending.at("parent"),
        .output_place = sending.at("output_place"),
        .timestamp = sending.at("timestamp"),
      };
      sendings.push_back(ss);
    }

    // get function calls
    for (const auto& function_call : statements.at("function_call")) {
      FunctionCallStatement fcs = {
        .function_name = function_call.at("function_name"),
        .input_place = function_call.at("input_place"),
        .parent = function_call.at("parent"),
        .output_place = function_call.at("output_place"),
      };
      function_calls.push_back(fcs);
    }

    // get branchings
    for (const auto& branching : statements.at("branching")) {
      BranchingStatement bs = {
        .variable = branching.at("variable"),
        .input_place = branching.at("input_place"),
        .parent = branching.at("parent"),
        .output_place = branching.at("output_place"),
        .timestamp = branching.at("timestamp"),
      };
      branchings.push_back(bs);
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
      if (sending.variable == variable){
          return sending.output_place;
        }
      }      
  }

  std::string LTLTranslator::get_assignment_output_place(std::string variable){
    for (const auto& assignment: assignments) {
      if (assignment.variable == variable){
          return assignment.output_place;
        }
      }      
  }

  std::string LTLTranslator::get_branching_output_place(std::string variable){
    for (const auto& branching: branchings) {
      if (branching.variable == variable){
          return branching.output_place;
        }
      }      
  }

  std::string LTLTranslator::get_function_call_output_place(std::string function_name){
    for (const auto& function_call: function_calls) {
      if (function_call.function_name == function_name){
          return function_call.output_place;
        }
    }
    throw(function_name);  
  }

  std::string LTLTranslator::get_function_call_input_place(std::string function_name){
    for (const auto& function_call: function_calls) {
      if (function_call.function_name == function_name){
          return function_call.input_place;
        }
    }
    throw(function_name);  
  }

  std::string LTLTranslator::get_timestamp_output_place(){
    for (const auto& assignment: assignments) {
      if (assignment.timestamp){
        return assignment.output_place;
      }
    }
    return "";     
  }
  // TODO: case timestamp doesn't exist: property is verified automatically ?
  bool LTLTranslator::timestamp_exists(){
    for (const auto& assignment: assignments) {
      if (assignment.timestamp){
        return true;
      }
    }
    return false;     
  }

  std::string LTLTranslator::get_read_output_place(std::string variable){
    for (const auto& assignment: assignments) {
      for (const auto& RHVariable: assignment.RHV){
        if (RHVariable == variable){
          return assignment.output_place;
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
          return checkAlwaysLessThan(inputs); 
        case(AlwaysMoreThan):
          return checkAlwaysMoreThan(inputs); 
        case(AlwaysEqual):
          return checkAlwaysEqual(inputs); 
        case(IsCalled):
          return checkIsCalled(inputs); 
        case(IsNeverCalled):
          return checkIsNeverCalled(inputs); 
        case(IsExecuted):
          return checkIsExecuted(inputs); 
        // case(IsNeverExecuted):
        //   return checkIsNeverExecuted(inputs); 
        // case(SequentialCall):
        //   return checkIsSequential(inputs); 
        // case(InfiniteLoop):
        //   return checkIsInfinite(inputs); 
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
  // TODO: Error handling
  std::map<std::string, std::string> LTLTranslator::detectReentrancy(nlohmann::json inputs) {
    try {
      std::string sending_output_place = get_sending_output_place(inputs.at("selected_variable"));
      // First version
      if(inputs.at("rival_contract").empty()){
        std::string assignment_output_place = get_assignment_output_place(inputs.at("selected_variable"));

        result["property"] = "ltl property reentrancy: [] ( not ( not assignment until sending) );";
        result["propositions"] = "proposition assignment: (" + assignment_output_place +"'card > 0) \
        proposition sending: ("+ sending_output_place +"'card > 0)";
      }
      // Second version
      // TODO: find alternative to X operator 
      else {
        std::string fallback_output_place = get_function_call_output_place("fallback");
        result["property"] = "ltl property reentrancy: sending => X [] (( not sending) until end_fallback);";
        result["propositions"] = "proposition sending: "+ sending_output_place +"'card > 0 \
                                  proposition end_fallback: " + fallback_output_place + "'card > 0";
      }
      return result;
    }
    catch(std::string e) {
      std::cerr << "There is no function call of function: " << e << '\n';
    }
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

  std::map<std::string, std::string> LTLTranslator::checkAlwaysEqual(nlohmann::json inputs) {
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


  std::map<std::string, std::string> LTLTranslator::checkIsCalled(nlohmann::json inputs) {
    std::string function_name = inputs.at("selected_function");
    std::string function_input_place = get_function_call_input_place(function_name);
    result["property"] = "ltl property called: funcall";
    result["propositions"] = "proposition funcall: "+ function_input_place +"'card > 0";
    return result;
  }  
  
  std::map<std::string, std::string> LTLTranslator::checkIsNeverCalled(nlohmann::json inputs) {
    std::string function_name = inputs.at("selected_function");
    std::string function_input_place = get_function_call_input_place(function_name);
    result["property"] = "ltl property uncalled: [] not funcall";
    result["propositions"] = "proposition funcall: "+ function_input_place + "'card > 0";
    return result;
  }  

  std::map<std::string, std::string> LTLTranslator::checkIsExecuted(nlohmann::json inputs) {
    std::string function_name = inputs.at("selected_function");
    std::string function_output_place = get_function_call_output_place(function_name);
    result["property"] = "ltl property executed: funexec";
    result["propositions"] = "proposition funexec: " + function_output_place + "'card > 0";
    return result;
  }  

  std::map<std::string, std::string> LTLTranslator::checkIsNeverExecuted(nlohmann::json inputs) {
    std::string function_name = inputs.at("selected_function");
    std::string function_output_place = get_function_call_output_place(function_name);
    result["property"] = "ltl property executed: G not funexec";
    result["propositions"] = "proposition funexec: " + function_output_place + "'card > 0";
    return result;
  }  

}  // namespace LTL2PROP