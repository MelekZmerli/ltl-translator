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
    if (vulnerability == "Is Always Called") return IsAlwaysCalled;
    if (vulnerability == "Is Never Called") return IsNeverCalled;
    if (vulnerability == "Is Executed") return IsExecuted;
    if (vulnerability == "Sequential Call") return SequentialCall;
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
        .smart_contract = assignment.at("smart_contract"),
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

  std::list<std::string> LTLTranslator::get_timestamp_places(){
    std::list<std::string> timestamp_places;
    for (const auto& assignment: assignments) {
      if (assignment.timestamp){
        timestamp_places.push_back(assignment.output_place);
      }
    }

    for (const auto& branching: branchings) {
      if (branching.timestamp){
        timestamp_places.push_back(branching.output_place);
      }
    }

    return timestamp_places;     
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

  std::map<std::string, std::string> LTLTranslator::detectSelfDestruction(std::string variable, std::string rival_contract="") {
    std::string branching_output_place = get_branching_output_place(variable);
    // First Formula 
    if (rival_contract.empty()){
      result["property"] = "ltl property selfdestruction: not testonbalance;";
      result["proposition"] = "proposition testonbalance:  "+ branching_output_place +"'card > 0;";
    }
    // Second Formula
    else{
      std::string function_call_output_place = get_function_call_output_place("selfdestruct");

      result["property"] = "ltl property selfdestruction: (not testonbalance) or (not selfdestruct until start)";
      result["propositions"] = "proposition testonbalance:"+ branching_output_place +"'card > 0; \
                                proposition selfdestruct:"+ function_call_output_place +"'card > 0; \
                                proposition start: ??????;"; // TODO: start proposition // function call of f in Si
    }
    return result;
  }
  // TODO: Error handling
  std::map<std::string, std::string> LTLTranslator::detectReentrancy(std::string variable, std::string rival_contract ="") {
    try {
      std::string sending_output_place = get_sending_output_place(variable);
      // First version
      if(rival_contract.empty()){
        std::string assignment_output_place = get_assignment_output_place(variable);

        result["property"] = "ltl property reentrancy: [] ( not ( not assignment until sending) );";
        result["propositions"] = "proposition assignment: (" + assignment_output_place +"'card > 0); \
        proposition sending: ("+ sending_output_place +"'card > 0);";
      }
      // Second version
      // TODO: find alternative to X operator 
      else {
        std::string fallback_output_place = get_function_call_output_place("fallback");
        result["property"] = "ltl property reentrancy: sending => X [] (( not sending) until end_fallback);";
        result["propositions"] = "proposition sending: "+ sending_output_place +"'card > 0; \
                                  proposition end_fallback: " + fallback_output_place + "'card > 0;";
      }
      return result;
    }
    catch(std::string e) {
      std::cerr << "There is no function call of function: " << e << '\n';
    }
  }

  std::map<std::string, std::string> LTLTranslator::detectTimestampDependance() {
    if(timestamp_exists()){
      std::list<std::string> places = get_timestamp_places();
      result["property"] = "ltl property tsindependant: [] not (";
      for (auto const& place: places)
      {
        if (place != places.back()) { 
          result["propositions"].append("property timestamp"+place+" : "+ place +"'card > 0;\n");
          result["property"].append("timestamp"+place+" or ");
        }
        else {
          result["propositions"].append("property timestamp"+place+" : "+ place +"'card > 0;\n");
          result["property"].append("timestamp"+place+");");
        } 
      }
    }
    else {
      result["property"] = "ltl property tsindependant: true;";
    }
    std::cout << result["property"]<<std::endl;
    std::cout << result["propositions"]<<std::endl;

    return result;
  }

  std::map<std::string, std::string> LTLTranslator::detectUninitializedStorageVariable(std::string variable) {
    std::string write_output_place = get_assignment_output_place(variable);
    std::string read_output_place = get_read_output_place(variable);

    result["property"] = "ltl property usv: not read until write;";
    result["propostions"] = "proposition read: exists(t in " + read_output_place + ") | (t->1).X'card > 0); \
                             proposition write: exists(t in " + write_output_place +" | (t->1).X'card > 0);";
  }

  std::map<std::string, std::string> LTLTranslator::detectUnderOverFlowVul(std::string variable, std::string min_threshold, std::string max_threshold) {
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

  std::map<std::string, std::string> LTLTranslator::detectSkipEmptyStringLiteral(std::string function){
      result["property"] = "ltl property skipempty: [] not emptyparam;";
      result["propositions"] = "exists (t in " + function + "_PAR | ((t->1)'space > 0) and ((t->1)'last'card > 0));";
      return result;

  }


  std::map<std::string, std::string> LTLTranslator::checkAlwaysLessThan(std::string variable, std::string rival_variable="", std::string max_threshold =""){


    result["property"] = "ltl property smaller: [] not more;";

    if(rival_variable.empty()){
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


  std::map<std::string, std::string> LTLTranslator::checkAlwaysMoreThan(std::string variable, std::string rival_variable = "", std::string min_threshold = ""){
    result["property"] = "ltl property bigger: [] not less;";
    
    if(rival_variable.empty()){
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
      std::string rival_variable = rival_variable;
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

  std::map<std::string, std::string> LTLTranslator::checkAlwaysEqual(std::string variable, std::string rival_variable="", std::string constant="") {
    result["property"] = "ltl property equals: [] not different;";
    
    if(rival_variable.empty()){
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


  std::map<std::string, std::string> LTLTranslator::checkIsAlwaysCalled(std::string function_name) {
    std::string function_input_place = get_function_call_input_place(function_name);
    result["property"] = "ltl property called: <> funcall;";
    result["propositions"] = "proposition funcall: "+ function_input_place +"'card > 0;";
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::checkIsNeverCalled(std::string function_name) {
    std::string function_input_place = get_function_call_input_place(function_name);
    result["property"] = "ltl property uncalled: [] not funcall;";
    result["propositions"] = "proposition funcall: "+ function_input_place + "'card > 0;";
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::checkIsExecuted(std::string function_name) {
    std::string function_output_place = get_function_call_output_place(function_name);
    result["property"] = "ltl property executed: []( funcall => <> funexec);";
    result["propositions"] = "proposition funexec: " + function_output_place + "'card > 0;";
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::checkIsSequential(std::string function_name, std::string rival_function) {
    std::string function_input_place = get_function_call_input_place(function_name);
    std::string rival_function_input_place = get_function_call_input_place(rival_function);

    result["property"] = "property sequential: [] funcallA => <> funcallB;";
    result["propositions"] = "proposition funcallA: " + function_input_place + "'card > 0;\
                              proposition funcallB: " + rival_function_input_place + "'card > 0;";
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::translate() {
    // get the type of formula : general or specific
    std::string formula_type = formula_json.at("type");
    auto formula_params = formula_json.at("params");
    std::string vulnerability_name = formula_params.at("name");

    // parse a general vulnerability formula
    if (formula_type == "general") {
      nlohmann::json inputs = formula_params.at("inputs");
      switch(LTLTranslator::getVulnerability(vulnerability_name)){
        case(IntegerOverflowUnderflow):{
          std::string min_threshold = inputs.at("min_threshold");
          std::string max_threshold = inputs.at("max_threshold");
          std::string variable = inputs.at("selected_variable");
          return detectUnderOverFlowVul(variable, min_threshold, max_threshold);
        }
        case(SelfDestruction):{
          std::string variable = inputs.at("selected_variable");
          std::string rival_contract = inputs.at("rival_contract");
          return detectSelfDestruction(variable, rival_contract);
        }
        case(Reentrancy):
          return detectReentrancy(inputs);
        case(TimestampDependence):
          return detectTimestampDependance();
        case(SkipEmptyStringLiteral):{
          std::string function = inputs.at("selected_function");
          return detectSkipEmptyStringLiteral(inputs);
        }
        case(UninitializedStorageVariable):{
          std::string variable = inputs.at("selected_variable");
          return detectUninitializedStorageVariable(variable);
        }
        case(AlwaysLessThan):{
          std::string variable = inputs.at("selected_variable");
          std::string rival_variable = inputs.at("rival_variable");
          std::string max_threshold = inputs.at("constant");
          return checkAlwaysLessThan(variable, rival_variable, max_threshold); 
        }
        case(AlwaysMoreThan):{
          std::string variable = inputs.at("selected_variable");
          std::string rival_variable = inputs.at("rival_variable");
          std::string min_threshold = inputs.at("constant");
          return checkAlwaysMoreThan(variable,rival_variable,min_threshold);
        }
        case(AlwaysEqual):{
          std::string variable = inputs.at("selected_variable");
          std::string rival_variable = inputs.at("rival_variable");
          std::string min_threshold = inputs["constant"];
          return checkAlwaysEqual(variable, rival_variable, min_threshold); 
        }
        case(IsAlwaysCalled):{
          std::string function_name = inputs.at("selected_function");
          return checkIsAlwaysCalled(function_name);
        }
        case(IsNeverCalled):{
          std::string function_name = inputs.at("selected_function");
          return checkIsNeverCalled(function_name);}
        case(IsExecuted):{
          std::string function_name = inputs.at("selected_function");
          return checkIsExecuted(function_name);} 
        case(SequentialCall):{
          std::string function_name = inputs.at("selected_function");
          std::string rival_function = inputs.at("rival_function");
          return checkIsSequential(function_name, rival_function);
        }
      }
    }
    else if (formula_type == "specific") {
      result["property"] = formula_params.at("property");
      result["propositions"] = formula_params.at("propositions");
      return result;
    }

    // throw an exception since the type cannot be handled
    throw std::runtime_error("formula type " + vulnerability_name + " is not handled by LTLTranslator");
  }

}  // namespace LTL2PROP
