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
    if (vulnerability == "Sequential Exec") return SequentialExec;
    if (vulnerability == "Call Followed By Exec") return CallFollowedByExec;
    if (vulnerability == "Exec Followed By Call") return ExecFollowedByCall;
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

    statement_list = lna_json.at("statements");
    // get statements
    for (const auto& statement : statement_list) {
      Statement s = {
        .type = statement.at("type"),
        .smart_contract = statement.at("smart_contract"),
        .parent = statement.at("parent"),
        .variable = statement.at("variable"),
        .function_name = statement.at("function"),
        .input_place = statement.at("input_place"),
        .output_place = statement.at("output_place"),
        .param_place = statement.at("param_place"),
        .RHV = statement["right_hand_variables"].get<std::list<std::string>>(),
        .timestamp = statement.at("timestamp"),
      };
      
      // assign statements to their respective lists
      if (s.type=="assignment") assignments.push_back(s);
      if (s.type=="selection") selections.push_back(s);
      if (s.type=="sending") sendings.push_back(s);
      if (s.type=="function_call") function_calls.push_back(s);
      if (s.type=="variable_declaration") variable_declarations.push_back(s);
      if (s.type=="return") returnings.push_back(s);
      if (s.type=="require") requirements.push_back(s);
      if (s.type=="for_loop") for_loops.push_back(s);
      if (s.type=="while_loop") while_loops.push_back(s);
      
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

  std::list<std::string> LTLTranslator::get_sending_output_places(std::string function){
    std::list<std::string> sending_output_places;
    for (const auto& sending: sendings) {
      if (sending.parent == function && !sending.output_place.empty()){
           sending_output_places.push_back(sending.output_place);
        }
      } 
    if(sending_output_places.empty()){
      std::runtime_error("There are no sending statements in this smart contract");
    }
    sending_output_places.unique();
    return sending_output_places;     
  }


  std::list<std::string> LTLTranslator::get_selection_output_places(std::string variable,std::string function, std::string smart_contract){
    std::list<std::string> selection_output_places;
    for (const auto& selection: selections) {
      if(selection.smart_contract == smart_contract && selection.parent == function && !selection.output_place.empty()){
        if (selection.variable == variable){
            selection_output_places.push_back(selection.output_place);
        }
        else if(!selection.RHV.empty()){
          for (auto &RHVariable : selection.RHV){
            if(RHVariable == variable){
              selection_output_places.push_back(selection.output_place);
            }
          }
        }
      } 
    }
    selection_output_places.unique();
    return selection_output_places;  
  }

  // get all variables that were affected address(this).balance value
  // we look in assignment and variable declaration statements
  std::list<std::string> LTLTranslator::get_balance_variables(std::string function, std::string smart_contract=""){
    std::list<std::string> balance_variables = {"address(this).balance"};
    for (auto &assignment : assignments){
        // for reentrancy variable, smart contract is not provided so we only check for function
      if (assignment.parent == function && (assignment.smart_contract == smart_contract || smart_contract.empty())) {
        if (!assignment.RHV.empty()){
          for (auto &RHVariable : assignment.RHV) {
            if (RHVariable == "address(this).balance") {
              balance_variables.push_back(assignment.variable);
            }
          }
        }
      }
    }

    for (auto &variable_declaration : variable_declarations){
        // for reentrancy variable, smart contract is not provided so we only check for function
       if (variable_declaration.parent == function && (variable_declaration.smart_contract == smart_contract || smart_contract.empty())) {
          if (!variable_declaration.RHV.empty()){
            for (auto &RHVariable : variable_declaration.RHV) {
              if (RHVariable == "address(this).balance") {
                balance_variables.push_back(variable_declaration.variable);
              }
            }
          }
       }
    }
    return balance_variables; 
  }

  std::list<std::string> LTLTranslator::get_for_loops_output_places(std::string variable,std::string function, std::string smart_contract){
    std::list<std::string> for_loop_output_places;
    for (const auto& for_loop: for_loops) {
      if(for_loop.smart_contract == smart_contract && for_loop.parent == function){
        if (for_loop.variable == variable && !for_loop.output_place.empty()){
            for_loop_output_places.push_back(for_loop.output_place);
          }
        else if(!for_loop.RHV.empty()){
          for (auto &RHVariable : for_loop.RHV){
            if(RHVariable == variable && !for_loop.output_place.empty()){
              for_loop_output_places.push_back(for_loop.output_place);
            }
          }
        }
      } 
    }
    for_loop_output_places.unique();
    return for_loop_output_places;  
  }

  std::list<std::string> LTLTranslator::get_while_loops_output_places(std::string variable,std::string function, std::string smart_contract){
    std::list<std::string> while_loop_output_places;
    for (const auto& while_loop: while_loops) {
      if(while_loop.smart_contract == smart_contract && while_loop.parent == function){
        if (while_loop.variable == variable && !while_loop.output_place.empty()){
            while_loop_output_places.push_back(while_loop.output_place);
          }
        else if(!while_loop.RHV.empty()){
          for (auto &RHVariable : while_loop.RHV){
            if(RHVariable == variable  && !while_loop.output_place.empty()){
              while_loop_output_places.push_back(while_loop.output_place);
            }
          }
        }
      } 
    }
    while_loop_output_places.unique();
    return while_loop_output_places;  
  }

  std::list<std::string> LTLTranslator::get_require_output_places(std::string variable,std::string function, std::string smart_contract){
    std::list<std::string> require_output_places;
    for (const auto& require: requirements) {
      if(require.smart_contract == smart_contract && require.parent == function && !require.output_place.empty()){
        if (require.variable == variable){
            require_output_places.push_back(require.output_place);
        }
        else if(!require.RHV.empty()){
          for (auto &RHVariable : require.RHV){
            if(RHVariable == variable){
              require_output_places.push_back(require.output_place);
            }
          }
        }
      } 
    }
    return require_output_places;  
  }

  std::list<std::string> LTLTranslator::get_function_call_output_places(std::string function_name, std::string smart_contract){
    std::list<std::string> function_call_output_places;
    for (const auto& function_call: function_calls) {
      if (function_call.function_name == function_name && function_call.smart_contract == smart_contract && !function_call.output_place.empty()){
          function_call_output_places.push_back(function_call.output_place);
      }
    }

    function_call_output_places.unique();
    return function_call_output_places;
  }

  std::list<std::string> LTLTranslator::get_function_call_input_places(std::string function_name,std::string smart_contract){
    std::list<std::string> function_call_input_places;
    for (const auto& function_call: function_calls) {
      if (function_call.function_name == function_name && function_call.smart_contract == smart_contract && !function_call.input_place.empty()){
          function_call_input_places.push_back(function_call.input_place);
      }
    }
    function_call_input_places.unique(); 
    return function_call_input_places;
  }

  std::list<std::string> LTLTranslator::get_timestamp_places(std::string function_name, std::string smart_contract){
    std::list<std::string> timestamp_places;
    for (const auto& assignment: assignments) {
      if (assignment.timestamp && assignment.function_name == function_name && assignment.smart_contract == smart_contract && !assignment.output_place.empty()){
        timestamp_places.push_back(assignment.output_place);
      }
    }

    for (const auto& selection: selections) {
      if (selection.timestamp && selection.function_name == function_name && selection.smart_contract == smart_contract && !selection.output_place.empty()){
        timestamp_places.push_back(selection.output_place);
      }
    }

    for (const auto& sending: sendings) {
      if (sending.timestamp && sending.function_name == function_name && sending.smart_contract == smart_contract && !sending.output_place.empty()){
        timestamp_places.push_back(sending.output_place);
      }
    }

    for (const auto& requirement: requirements) {
      if (requirement.timestamp && requirement.function_name == function_name && requirement.smart_contract == smart_contract && !requirement.output_place.empty()){
        timestamp_places.push_back(requirement.output_place);
      }
    }

    for (const auto& function_call: function_calls) {
      if (function_call.timestamp && function_call.parent == function_name && function_call.smart_contract == smart_contract && !function_call.output_place.empty()){
        timestamp_places.push_back(function_call.output_place);
      }
    }

    for (const auto& variable_declaration: variable_declarations) {
      if (variable_declaration.timestamp && variable_declaration.function_name == function_name && variable_declaration.smart_contract == smart_contract && !variable_declaration.output_place.empty()){
        timestamp_places.push_back(variable_declaration.output_place);
      }
    }

    for (const auto& returning: returnings) {
      if (returning.timestamp && returning.function_name == function_name && returning.smart_contract == smart_contract && !returning.output_place.empty()){
        timestamp_places.push_back(returning.output_place);
      }
    }

    for (const auto& for_loop: for_loops) {
      if (for_loop.timestamp && for_loop.function_name == function_name && for_loop.smart_contract == smart_contract && !for_loop.output_place.empty()){
        timestamp_places.push_back(for_loop.output_place);
      }
    }

    for (const auto& while_loop: while_loops) {
      if (while_loop.timestamp && while_loop.function_name == function_name && while_loop.smart_contract == smart_contract && !while_loop.output_place.empty()){
        timestamp_places.push_back(while_loop.output_place);
      }
    }
    timestamp_places.unique();
    return timestamp_places;     
  }


  // returns output places for following statements (variable x)
  // int x = y;
  // x = y;
  std::list<std::string> LTLTranslator::get_write_output_places(std::string variable, std::string function){
    std::list<std::string> write_places;
    for(auto &assignment : assignments) {
      if (assignment.variable == variable && !assignment.output_place.empty()) {
        write_places.push_back(assignment.output_place);
      }
    }
    for(auto &declaration: variable_declarations) {
      if (declaration.variable == variable && !declaration.RHV.empty() && !declaration.output_place.empty()) {
        write_places.push_back(declaration.output_place);
      }
    }
    return write_places;     
  }

  // returns cases for variable x
  // int x = y;
  // x = y;
  std::list<std::string> LTLTranslator::get_read_output_places(std::string variable, std::string function){
    std::list<std::string> read_places;
    for (const auto& assignment: assignments) {
      for (const auto& RHVariable: assignment.RHV){
        if (RHVariable == variable && !assignment.output_place.empty()){
          read_places.push_back(assignment.output_place);
        } 
      }
    }

    for (const auto& selection: selections) {
      for (const auto& RHVariable: selection.RHV){
        if (RHVariable == variable && !selection.output_place.empty()){
          read_places.push_back(selection.output_place);
        } 
      }
    }

    for (const auto& variable_declaration: variable_declarations) {
      for (const auto& RHVariable: variable_declaration.RHV){
        if (RHVariable == variable && !variable_declaration.output_place.empty()){
          read_places.push_back(variable_declaration.output_place);
        } 
      }
    }

    for (const auto& requirement: requirements) {
      for (const auto& RHVariable: requirement.RHV){
        if (RHVariable == variable && !requirement.output_place.empty()){
          read_places.push_back(requirement.output_place);
        } 
      }
    }

    for (const auto& returning: returnings) {
      for (const auto& RHVariable: returning.RHV){
        if (RHVariable == variable && !returning.output_place.empty()){
          read_places.push_back(returning.output_place);
        } 
      }
    }

    for (const auto& sending: sendings) {
      for (const auto& RHVariable: sending.RHV){
        if (RHVariable == variable && !sending.output_place.empty()){
          read_places.push_back(sending.output_place);
        } 
      }
    }

    for (const auto& for_loop: for_loops) {
      for (const auto& RHVariable: for_loop.RHV){
        if (RHVariable == variable && !for_loop.output_place.empty()){
          read_places.push_back(for_loop.output_place);
        } 
      }
    }

    for (const auto& while_loop: while_loops) {
      for (const auto& RHVariable: while_loop.RHV){
        if (RHVariable == variable && !while_loop.output_place.empty()){
          read_places.push_back(while_loop.output_place);
        } 
      }
    }


    return read_places;  
  }

  std::list<std::string> LTLTranslator::get_function_call_param_places(std::string function){
    std::list<std::string> function_call_param_places;
    for (auto &function_call : function_calls) {
      if(function_call.parent == function){
        function_call_param_places.push_back(function_call.param_place);
      }
    }
    function_call_param_places.unique();
    return function_call_param_places;
  }

  std::list<std::string> LTLTranslator::get_balance_variables_testing_output_places(std::list<std::string> balance_variables, std::string function, std::string smart_contract){
    std::list<std::string> balance_testing_output_places;
    for (auto &balance_variable : balance_variables) {
      std::list<std::string> selection_output_places = get_selection_output_places(balance_variable,function,smart_contract);
      std::list<std::string> for_loop_output_places = get_for_loops_output_places(balance_variable,function,smart_contract);
      std::list<std::string> while_loop_output_places = get_while_loops_output_places(balance_variable,function,smart_contract);
      std::list<std::string> require_output_places = get_require_output_places(balance_variable,function,smart_contract);

      // merge all output places of statements that have tests on balance variables
      balance_testing_output_places.merge(selection_output_places);
      balance_testing_output_places.merge(for_loop_output_places);
      balance_testing_output_places.merge(while_loop_output_places);
      balance_testing_output_places.merge(require_output_places);
    }

    balance_testing_output_places.unique();
    return balance_testing_output_places;
  }

  // get assignment (assignment and variable declaration statements) output places for all variables that are affected  
  std::list<std::string> LTLTranslator::get_balance_variables_write_statements(std::list<std::string> balance_variables, std::string function){
    std::list<std::string> assignment_output_places;
    for (auto &balance_variable : balance_variables){
      assignment_output_places.merge(get_write_output_places(balance_variable, function));
    }
    assignment_output_places.unique();
    return assignment_output_places;
  }

  std::map<std::string, std::string> LTLTranslator::detectSelfDestruction(std::string function,std::string smart_contract, std::string rival_contract) {
    // get all variables that are equal to address(this).balance
    std::list<std::string> balance_variables = get_balance_variables(function,smart_contract);
    std::list<std::string> balance_testing_output_places = get_balance_variables_testing_output_places(balance_variables, function, smart_contract);


    // if there's no testing on balance variable, vulnerability doesn't exist.
    if(balance_testing_output_places.empty()){
      result["property"] = "ltl property selfdestruction: true";
    }
    
    // First Formula : ltl property selfdestruction: not testonbalance ;
    else if(rival_contract.empty()){
      result["property"] = "ltl property selfdestruction: not (";
      for (auto &balance_testing_output_place : balance_testing_output_places){
        result["propositions"].append("proposition testonbalance" +balance_testing_output_place +" : "+ balance_testing_output_place +"'card > 0;\n");
        if (balance_testing_output_place != balance_testing_output_places.back()) { 
          result["property"].append(" testonbalance" + balance_testing_output_place +" or ");
        }
        else {
          result["property"].append(" testonbalance" + balance_testing_output_place +" ); ");
        } 
      }
    }

    // Second Formula :  ltl property selfdestruction: ( not testonbalance ) or ( not selfdestruct U start );
    else{

      // get balance testonbalance properties
      result["property"] = "ltl property selfdestruction: (not ";
      for (auto &balance_testing_output_place : balance_testing_output_places){
        result["propositions"].append("proposition testonbalance" +balance_testing_output_place +" : "+ balance_testing_output_place +"'card > 0;\n");
        if (balance_testing_output_place != balance_testing_output_places.back()) { 
          result["property"].append(" testonbalance" + balance_testing_output_place +" or ");
        }
        else {
          result["property"].append(" testonbalance" + balance_testing_output_place +" ) or ( not ( ");
        } 
      }

      try{
        std::list<std::string> rival_function_call_output_places = get_function_call_output_places("selfdestruct", rival_contract);
        // get selfdestruct propositions
        for (auto &rival_function_call_output_place : rival_function_call_output_places) {
        result["propositions"].append("proposition selfdestruct"+rival_function_call_output_place + " : " + rival_function_call_output_place +"'card > 0;\n");
          if(rival_function_call_output_place != rival_function_call_output_places.back()){
            result["property"].append("selfdestruct"+rival_function_call_output_place +" or ");
          }
          else {
            result["property"].append("selfdestruct"+rival_function_call_output_place +" ) until ( ");
          }
        }
      }
      // if selfdestruct function is never called in rival contract, contract isn't vulnerable to selfdestruction exploits.
      catch(std::runtime_error e){
        result["property"] = "ltl property selfdestruction: true;";
        result["propositions"].clear();
        return result;
      }


      try{
        std::list<std::string> function_call_input_places = get_function_call_input_places(function, smart_contract);
        // get start propositions
        for (auto &function_call_input_place : function_call_input_places) {
          result["propositions"].append("proposition start" + function_call_input_place + " : " + function_call_input_place + "'card > 0;\n");
          if(function_call_input_place != function_call_input_places.back()){
            result["property"].append("start" + function_call_input_place + " or ");
          }
          else {
            result["property"].append("start" + function_call_input_place + " )); ");
          } 
        }
      }
      // if tested function isn't called in context execution then function is not vulnerable to self destruction exploits
      // Q? directly true or keep propositions and replace it with until false instead of until start
      catch(std::runtime_error e){
        result["property"] = "ltl property selfdestruction: true;";
        result["propositions"].clear();
      }
    }  
    return result;
  }


  // ltl property reentrancy: [ ] not (( not assignment ) until (sending))
  std::map<std::string, std::string> LTLTranslator::detectReentrancy(std::string variable, std::string function) {
    std::list<std::string> balance_variables = get_balance_variables(function);
    std::list<std::string> sending_output_places = get_sending_output_places(function);
    std::list<std::string> assignment_output_places = get_balance_variables_write_statements(balance_variables, function);
    result["property"] = "ltl property reentrancy: [] not (not (";


    // in case there aren't any sending statements in context, smart contract isn't vulnerable to reentrancy attacks.
    if(sending_output_places.empty()){
      result["property"] = "ltl property reentrancy: true;";
      return result;
    }
    // in case there are sending statements but there are no assignment to variable we only check if there are sendings.
    // Q? false OR replace it with false instead of assignment in reentrancy property OR [] not sending
    else if(assignment_output_places.empty()){
      result["property"] = "ltl property reentrancy: [] not (";  
      // get sending propositions
      for (auto &sending_output_place : sending_output_places){
        result["propositions"].append("proposition sending" + sending_output_place + " : (" + sending_output_place + "'card > 0);\n");
        if(sending_output_place != sending_output_places.back()){
          result["property"].append("sending"+sending_output_place +" or ");
        }
        else {
          result["property"].append("sending"+sending_output_place +"));");
        }          
      }     
    }
    // there are sending and assignment properties
    else {
      // get assignment propositions

      for (auto &assignment_output_place : assignment_output_places){
        result["propositions"].append("proposition assignment" + assignment_output_place + " : (" + assignment_output_place + "'card > 0);\n");
        if(assignment_output_place != assignment_output_places.back()){
          result["property"].append("assignment"+assignment_output_place +" or ");
        }
        else {
          result["property"].append("assignment"+assignment_output_place +") until (");
        }          
      }
      

      // get sending propositions
      for (auto &sending_output_place : sending_output_places){
        result["propositions"].append("proposition sending" + sending_output_place + " : (" + sending_output_place + "'card > 0);\n");
        if(sending_output_place != sending_output_places.back()){
          result["property"].append("sending"+sending_output_place +" or ");
        }
        else {
          result["property"].append("sending"+sending_output_place +"));");
        }          
      } 
    }
    return result;       
}

std::map<std::string, std::string> LTLTranslator::detectTimestampDependance(std::string function_name, std::string smart_contract) {
  std::list<std::string> places = get_timestamp_places(function_name, smart_contract);
  if (!places.empty()){
    result["property"] = "ltl property tsindependant: [] not (";
    for (auto const& place: places)
    {
      result["propositions"].append("proposition timestamp"+place+" : "+ place +"'card > 0;\n");
      if (place != places.back()) { 
        result["property"].append("timestamp"+place+" or ");
      }
      else {
        result["property"].append("timestamp"+place+");");
      } 
    }
  }
  else {
    result["property"] = "ltl property tsindependant: true;";
  }

  return result;
  }

  std::map<std::string, std::string> LTLTranslator::detectUninitializedStorageVariable(std::string variable,std::string function) {
    std::list<std::string> write_output_places = get_write_output_places(variable, function);
    std::list<std::string> read_output_places = get_read_output_places(variable, function);

    //remove duplicates from both lists
    write_output_places.unique();
    read_output_places.unique();

    if(!read_output_places.empty()){
      result["property"] = "ltl property usv: not (";
      for (auto const& read_output_place: read_output_places)
      {
        if (read_output_place != read_output_places.back()) { 
          result["propositions"].append("proposition read"+read_output_place+" : "+ read_output_place +"'card > 0;\n");
          result["property"].append("read"+read_output_place+" or ");
        }
        else {
          result["propositions"].append("property read"+read_output_place+" : "+ read_output_place +"'card > 0;\n");
          result["property"].append("read"+read_output_place+") until (");
        } 
      }
    }
    // in case variable is never read in execution
    else
    {
      result["property"] = "ltl property usv: true;";
      return result;
    }

    if(!write_output_places.empty()){
      for (auto const& write_output_place: write_output_places)
      {
        if (write_output_place != write_output_places.back()) { 
          result["propositions"].append("proposition write"+write_output_place+" : "+ write_output_place +"'card > 0;\n");
          result["property"].append("write"+write_output_place+" or ");
        }
        else {
          result["propositions"].append("property write"+write_output_place+" : "+ write_output_place +"'card > 0;\n");
          result["property"].append("write"+write_output_place+" );");
        } 
      }
    }
    // in case, variable isn't assigned a value in execution
    else {
      result["property"] = "ltl property usv: false;";
      return result;
    }  
    return result;
  }

  std::map<std::string, std::string> LTLTranslator::detectIntegerUnderOverFlow(std::string variable, std::string min_threshold, std::string max_threshold) {
    result["property"] = "ltl property outOfRange: [] ( not OUFlow ) ;";
    if (is_global_variable(variable)) {
      result["propositions"] = "proposition OUFlow: exists (t in S | (t->1)." + variable + " < " + min_threshold +") or exists (t in S | (t->1)." + variable + " > " + max_threshold + ");";
    }
    else if (!local_variables[variable].empty())
    {
      std::string variable_place = local_variables[variable];

      result["propositions"] = "proposition OUFlow: exists (t in "+ variable_place + " | (t->1)." + variable + " < " + min_threshold +") or exists (t in "+ variable_place \
      +" | (t->1)." + variable + " > " + max_threshold + ");";
    }
    else{
      throw std::runtime_error("Variable " + variable + " doesn't exist in smart contract.");
    }
    
    return result;

  }
  // look for empty function calls INSIDE function variable
  std::map<std::string, std::string> LTLTranslator::detectSkipEmptyStringLiteral(std::string function){
    
    std::list<std::string> function_call_inside_function_param_places = get_function_call_param_places(function);
    if (function_call_inside_function_param_places.empty()) {
      result["property"] = "ltl property skipempty: true";
    }
    else {
      result["property"] = "ltl property skipempty: [] not (";
      for (auto &function_call_inside_function_param_place : function_call_inside_function_param_places) {
        // TODO: check another way to express proposition (structured types don't have any attributes)
        result["propositions"].append("proposition emptyparam" + function_call_inside_function_param_place + ": exists (t in " + function_call_inside_function_param_place + " | ((t->1)'space > 0) and ((t->1)'last'card > 0));\n");
        if(function_call_inside_function_param_place != function_call_inside_function_param_places.back()){
          result["property"].append("emptyparam" + function_call_inside_function_param_place + " or ");
        }
        else {
          result["property"].append("emptyparam" + function_call_inside_function_param_place + ");");
        }
      }
    }
    return result;
  }


  std::map<std::string, std::string> LTLTranslator::checkAlwaysLessThan(std::string variable, std::string rival_variable="", std::string max_threshold =""){

    result["property"] = "ltl property smaller: [] not more;";

    if(rival_variable.empty()){
      if (is_global_variable(variable)) {
        result["propositions"] = "proposition more: exists (t in S | (t->1)." + variable + " > " + max_threshold +");";
      }
      else {
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
      else {
        std::string variable_place = local_variables[variable];
        result["propositions"] = "proposition less: exists (t in "+ variable_place + " | (t->1)." + variable + " < " + min_threshold +");";
      }
    }
    else {
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


  std::map<std::string, std::string> LTLTranslator::checkIsAlwaysCalled(std::string function_name, std::string smart_contract) {
    std::list<std::string> function_call_input_places = get_function_call_input_places(function_name, smart_contract);
    if(function_call_input_places.empty()){
      result["property"] = "ltl property called: false;";
    }
    else{
      result["property"] = "ltl property called: <> ( ";

      for (auto &function_call_input_place : function_call_input_places) {
        result["propositions"].append("proposition funcall" + function_call_input_place +" : " + function_call_input_place +"'card > 0;\n");
        if (function_call_input_place != function_call_input_places.back()) {
          result["property"].append("funcall" + function_call_input_place +" or " );
        }
        else {
          result["property"].append("funcall" + function_call_input_place +" ); " );
        }
      }
    }
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::checkIsNeverCalled(std::string function_name,std::string smart_contract) {
    std::list<std::string> function_call_input_places = get_function_call_input_places(function_name, smart_contract);
    if(function_call_input_places.empty()){
      result["property"] = "ltl property uncalled: true;";
    }
    else{
      result["property"] = "ltl property uncalled: [] not ( ";
      for (auto &function_call_input_place : function_call_input_places) {
        result["propositions"].append("proposition funcall" + function_call_input_place +" : " + function_call_input_place +"'card > 0;\n");
        if (function_call_input_place != function_call_input_places.back()) {
          result["property"].append("funcall" + function_call_input_place +" or " );
        }
        else {
          result["property"].append("funcall" + function_call_input_place +" ); " );
        }
      }
    }
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::checkIsExecuted(std::string function_name,std::string smart_contract) {
    std::list<std::string> function_call_input_places = get_function_call_input_places(function_name, smart_contract);
    std::list<std::string> function_call_output_places = get_function_call_output_places(function_name, smart_contract);
    result["property"] = "ltl property executed: [] ( ";

    if(function_call_input_places.empty() || function_call_output_places.empty()){
      result["property"] = "ltl property executed: false;";
    } 
    else{
      // get all funcall propositions
      for (auto &function_call_input_place : function_call_input_places) {
        result["propositions"].append("proposition funcall" + function_call_input_place +" : " + function_call_input_place +"'card > 0;\n");
        if (function_call_input_place != function_call_input_places.back()) {
          result["property"].append("funcall" + function_call_input_place +" or " );
        }
        else {
          result["property"].append("funcall" + function_call_input_place +" ) => <> ( " );
        }
      }

      // get all funexec propositions
      for (auto &function_call_output_place : function_call_output_places) {
        result["propositions"].append("proposition funexec" + function_call_output_place +" : " + function_call_output_place +"'card > 0;\n");
        if (function_call_output_place != function_call_output_places.back()) {
          result["property"].append("funexec" + function_call_output_place +" or " );
        }
        else {
          result["property"].append("funexec" + function_call_output_place +" );" );
        }
      }
    }
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::checkIsSequentialCall(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract) {
    std::list<std::string> function_call_input_places = get_function_call_input_places(function_name, smart_contract);
    std::list<std::string> rival_function_call_input_places = get_function_call_input_places(rival_function, rival_contract);

    if (function_call_input_places.empty())
    {
    result["property"] = "property sequential: true;"; 
    }
    else if(rival_function_call_input_places.empty()){
    result["property"] = "property sequential: false;"; 
    }
    else{ 
      result["property"] = "property sequential: [] ( "; 
      // get all funcall A properties
      for (auto &function_call_input_place : function_call_input_places) {
        result["propositions"].append("proposition funcallA" + function_call_input_place +" : " + function_call_input_place +"'card > 0;\n");
        if (function_call_input_place != function_call_input_places.back()) {
          result["property"].append("funcallA" + function_call_input_place +" or " );
        }
        else {
          result["property"].append("funcallA" + function_call_input_place +" ) => <> ( " );
        }
      }
      // get all funcall B properties
      for (auto &rival_function_call_input_place : rival_function_call_input_places) {
        result["propositions"].append("proposition funcallB" + rival_function_call_input_place +" : " + rival_function_call_input_place +"'card > 0;\n");
        if (rival_function_call_input_place != rival_function_call_input_places.back()) {
          result["property"].append("funcallB" + rival_function_call_input_place +" or " );
        }
        else {
          result["property"].append("funcallB" + rival_function_call_input_place +" );" );
        }
      }
    }
    return result;
  }  


  std::map<std::string, std::string> LTLTranslator::checkIsSequentialExec(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract) {
    std::list<std::string> function_call_output_places = get_function_call_output_places(function_name, smart_contract);
    std::list<std::string> rival_function_call_output_places = get_function_call_output_places(rival_function, rival_contract);

    if (function_call_output_places.empty())
    {
    result["property"] = "property sequential: true;"; 
    }
    else if(rival_function_call_output_places.empty()){
    result["property"] = "property sequential: false;"; 
    }
    else{ 
      result["property"] = "property sequential: [] ( "; 
      // get all funcall A properties
      for (auto &function_call_output_place : function_call_output_places) {
        result["propositions"].append("proposition funcallA" + function_call_output_place +" : " + function_call_output_place +"'card > 0;\n");
        if (function_call_output_place != function_call_output_places.back()) {
          result["property"].append("funcallA" + function_call_output_place +" or " );
        }
        else {
          result["property"].append("funcallA" + function_call_output_place +" ) => <> ( " );
        }
      }
      // get all funcall B properties
      for (auto &rival_function_call_output_place : rival_function_call_output_places) {
        result["propositions"].append("proposition funcallB" + rival_function_call_output_place +" : " + rival_function_call_output_place +"'card > 0;\n");
        if (rival_function_call_output_place != rival_function_call_output_places.back()) {
          result["property"].append("funcallB" + rival_function_call_output_place +" or " );
        }
        else {
          result["property"].append("funcallB" + rival_function_call_output_place +" );" );
        }
      }
    }
    return result;
  }  

  std::map<std::string, std::string> LTLTranslator::checkCallFollowedByExec(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract) {
    std::list<std::string> function_call_input_places = get_function_call_input_places(function_name, smart_contract);
    std::list<std::string> rival_function_call_output_places = get_function_call_output_places(rival_function, rival_contract);

    if (function_call_input_places.empty()) {
      result["property"] = "property sequential: true;"; 
    }
    else if(rival_function_call_output_places.empty()){
      result["property"] = "property sequential: false;"; 
    }
    else{ 
      result["property"] = "property sequential: [] ( "; 
      // get all funcall A properties
      for (auto &function_call_input_place : function_call_input_places) {
        result["propositions"].append("proposition funcallA" + function_call_input_place +" : " + function_call_input_place +"'card > 0;\n");
        if (function_call_input_place != function_call_input_places.back()) {
          result["property"].append("funcallA" + function_call_input_place +" or " );
        }
        else {
          result["property"].append("funcallA" + function_call_input_place +" ) => <> ( " );
        }
      }
      // get all funcall B properties
      for (auto &rival_function_call_output_place : rival_function_call_output_places) {
        result["propositions"].append("proposition funcallB" + rival_function_call_output_place +" : " + rival_function_call_output_place +"'card > 0;\n");
        if (rival_function_call_output_place != rival_function_call_output_places.back()) {
          result["property"].append("funcallB" + rival_function_call_output_place +" or " );
        }
        else {
          result["property"].append("funcallB" + rival_function_call_output_place +" );" );
        }
      }
    }
    return result;
  }  

  std::map<std::string, std::string> LTLTranslator::checkExecFollowedByCall(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract) {
    std::list<std::string> function_call_output_places = get_function_call_output_places(function_name, smart_contract);
    std::list<std::string> rival_function_call_input_places = get_function_call_input_places(rival_function, rival_contract);

    if (function_call_output_places.empty())
    {
    result["property"] = "property sequential: true "; 
    }
    else if(rival_function_call_input_places.empty()){
    result["property"] = "property sequential: false "; 
    }
    else{ 
      result["property"] = "property sequential: [] ( "; 
      // get all funcall A properties
      for (auto &function_call_output_place : function_call_output_places) {
        result["propositions"].append("proposition funcallA" + function_call_output_place +" : " + function_call_output_place +"'card > 0;\n");
        if (function_call_output_place != function_call_output_places.back()) {
          result["property"].append("funcallA" + function_call_output_place +" or " );
        }
        else {
          result["property"].append("funcallA" + function_call_output_place +" ) => <> ( " );
        }
      }
      // get all funcall B properties
      for (auto &rival_function_call_input_place : rival_function_call_input_places) {
        result["propositions"].append("proposition funcallB" + rival_function_call_input_place +" : " + rival_function_call_input_place +"'card > 0;\n");
        if (rival_function_call_input_place != rival_function_call_input_places.back()) {
          result["property"].append("funcallB" + rival_function_call_input_place +" or " );
        }
        else {
          result["property"].append("funcallB" + rival_function_call_input_place +" );" );
        }
      }
    }
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

          result = detectIntegerUnderOverFlow(variable, min_threshold, max_threshold);
        }
        case(SelfDestruction):{
          std::string smart_contract = inputs.at("smart_contract");
          std::string function = inputs.at("selected_function");
          std::string rival_contract = inputs.at("rival_contract");

          return  detectSelfDestruction(function,smart_contract,rival_contract);
        }
        case(Reentrancy):{
          std::string variable = inputs.at("selected_variable");
          std::string function = inputs.at("selected_function");
  
          return  detectReentrancy(variable,function);
        }
        case(TimestampDependence):
          std::string function = inputs.at("selected_function");
          std::string smart_contract = inputs.at("smart_contract");

          return detectTimestampDependance(function, smart_contract);
        case(SkipEmptyStringLiteral):{
          std::string function = inputs.at("selected_function");

          return detectSkipEmptyStringLiteral(function);
        }
        case(UninitializedStorageVariable):{
          std::string variable = inputs.at("selected_variable");
          std::string function = inputs.at("selected_function");

          return detectUninitializedStorageVariable(variable, function);
        }
        case(AlwaysLessThan):{
          std::string variable = inputs.at("selected_variable");
          std::string rival_variable = inputs.at("rival_variable");
          std::string max_threshold = inputs.at("max_threshold");

          return checkAlwaysLessThan(variable, rival_variable, max_threshold); 
        }
        case(AlwaysMoreThan):{
          std::string variable = inputs.at("selected_variable");
          std::string rival_variable = inputs.at("rival_variable");
          std::string min_threshold = inputs.at("min_threshold");

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
          std::string smart_contract = inputs.at("smart_contract");

          return checkIsAlwaysCalled(function_name, smart_contract);
        }
        case(IsNeverCalled):{
          std::string function_name = inputs.at("selected_function");
          std::string smart_contract = inputs.at("smart_contract");

          return checkIsNeverCalled(function_name, smart_contract);
        }
        case(IsExecuted):{
          std::string function_name = inputs.at("selected_function");
          std::string smart_contract = inputs.at("smart_contract");

          result = checkIsExecuted(function_name,smart_contract);
        } 
        case(SequentialCall):{
          std::string function_name = inputs.at("selected_function");
          std::string smart_contract = inputs.at("smart_contract");
          std::string rival_function = inputs.at("rival_function");
          std::string rival_contract = inputs.at("rival_contract");

          return checkIsSequentialCall(function_name, smart_contract, rival_function, rival_contract);
        }
        case(SequentialExec):{
          std::string function_name = inputs.at("selected_function");
          std::string smart_contract = inputs.at("smart_contract");
          std::string rival_function = inputs.at("rival_function");
          std::string rival_contract = inputs.at("rival_contract");

        return checkIsSequentialExec(function_name, smart_contract, rival_function, rival_contract);
        }
        case(CallFollowedByExec):{
          std::string function_name = inputs.at("selected_function");
          std::string smart_contract = inputs.at("smart_contract");
          std::string rival_function = inputs.at("rival_function");
          std::string rival_contract = inputs.at("rival_contract");

          return checkCallFollowedByExec(function_name, smart_contract, rival_function, rival_contract);
        }
        case(ExecFollowedByCall):{
          std::string function_name = inputs.at("selected_function");
          std::string smart_contract = inputs.at("smart_contract");
          std::string rival_function = inputs.at("rival_function");
          std::string rival_contract = inputs.at("rival_contract");

          result = checkExecFollowedByCall(function_name, smart_contract, rival_function, rival_contract);

          std:: cout << result["propositions"]<< std::endl;
          std:: cout << result["property"]<< std::endl;
          return result;
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
//TODO: test execution of rest of the vulnerabilities

// reentrancy => DONE
// self-destruction => DONE
// integer under/overflow => DONE
// unitialized storage variable => DONE
// timestamp dependance => DONE


// TODO: handle null cases of json file