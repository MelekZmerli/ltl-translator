#ifndef LTLTRANSLATOR_HPP_
#define LTLTRANSLATOR_HPP_

#include <json.hpp>
#include <list>
#include <map>
#include <string>
#include <vector>

namespace LTL2PROP {


/**
 * @brief Class encapsulating the parser from LTL to Helena
 */
class LTLTranslator {
 public:
  /**
   * Create a new LTL translator
   *
   * @param lna_json JSON object containing the information of the CPN net
   * @param ltl_json JSON object containing the information of the LTL formula
   */
  LTLTranslator(const nlohmann::json& lna_json, const nlohmann::json& ltl_json);

  /**
   * Translate a LTL formula into Helena code
   *
   * @return the propositions and the property in Helena code
   */
  std::map<std::string, std::string> translate();

  /**
   * Get the list of variables in a formula
   *
   * @param _formula Helena formula
   * @return list of variables
   */
  static std::vector<std::string> getListVariableFromFormula(
      const std::string& _formula);

 private:
  struct Statement{
				std::string type;
				std::string smart_contract;
				std::string parent;
				std::string variable;
				std::string function_name;
				std::string input_place;
				std::string output_place;		
        std::string param_place;		
				std::list<std::string> RHV;
				bool timestamp;
  };

  // output map of translate() function
  std::map<std::string, std::string> result = { {"property", ""}, {"propositions", ""}};

  // json that contrains vulnerability / property info
  nlohmann::json formula_json;

  // all statements of selected smart contracts
  nlohmann::json statement_list;

  // all local variables of selected smart contracts
  std::map<std::string, std::string> local_variables;

  // all global variables of selected smart contracts
  std::list<std::string> global_variables;

  // each type of statement has its own list
  std::list<Statement> assignments,
   sendings, selections, function_calls,
  variable_declarations, returnings, requirements,
   for_loops, while_loops;






  // vulnerabilities and properties
  enum vulnerabilities {
    IntegerOverflowUnderflow,
    Reentrancy,
    TimestampDependence,
    SelfDestruction,
    SkipEmptyStringLiteral,
    UninitializedStorageVariable,
  };

  enum propertyTemplates {
    VariableAlwaysLessThan,
    VariableAlwaysMoreThan,
    VariableAlwaysEqualTo,
    FunctionIsEventuallyCalled,
    FunctionIsNeverCalled,
    FunctionIsExecuted,
    SequentialCall,
    SequentialExecution,
    CallFollowedByExec,
    ExecFollowedByCall
  };

  vulnerabilities getVulnerability(std::string vulnerability);

  propertyTemplates getPropertyTemplate(std::string propertyTemplate);

  /**
   * Create a map between the syntax of LTL operators and Helena
   */
  void createMap();

  /**
   * Parse global/local variables from a CPN JSON object
   *
   * @param lna_json JSON object containing information about a CPN net
   */
  void handleVariable(const nlohmann::json& lna_json);

  /**
   * Check if _name is a constant
   *
   * @param _name definition's name
   * @return true if it's a constant, false otherwise
   */
  bool is_const_definition(const std::string& _name) const;

  /**
   * Get the value of a constant
   *
   * @param _name name of the constant
   * @return value  of the constant
   */
  std::string get_const_definition_value(const std::string& _name);

  /**
   * Check if _name is a global variable
   *
   * @param _name name of the variable
   * @return true if the variable is global, false otherwise
   */
  bool is_global_variable(const std::string& _name) const;



  /**
   * Check if _name is a local variable
   *
   * @param _name name of the variable
   * @return true if the variable is local, false otherwise
   */
  bool is_local_variable(const std::string& _name) const;

  /**
   * Return the place modelling the local variable
   *
   * @param _name name of the local variable
   * @return name of the place
   */
  std::string get_local_variable_placetype(const std::string& _name);

  /**
   * Return the Helena code for the "Integer Overflow/Underflow" vulnerability
     @param variable variable being tested
     @param min_threshold minimum threshold value
     @param max_threshold maximum threshold value
   * @return Helena code
   */
    std::map<std::string, std::string> detectIntegerUnderOverFlow(std::string variable, std::string min_threshold, std::string max_threshold);
      
  /**
   * Return the Helena code for the "Reentrancy" vulnerability
   * @param inputs a json file that holds the following params:
   * if contract is totally free:     
        @param variable: variable being tested
        @param function: function used for sending
        @param smart_contract: smart contract that contains function

   * @return Helena code
   */
    std::map<std::string, std::string> detectReentrancy(
    std::string variable, std::string function, std::string smart_contract);

    

  /**
   * Return the Helena code for the "TimestampDestruction" vulnerability
   * @return Helena code
   */
    std::map<std::string, std::string> detectTimestampDependance(std::string function_name, std::string smart_contract);

  /**
   * Return the Helena code for the "Skip Empty String Literal" vulnerability
   * @param function name of the function whose params are going to be checked
   * @param smart_contract name of smart contract that contains 'function'
   *  
   * @return Helena code
   */
    std::map<std::string, std::string> detectSkipEmptyStringLiteral(
    std::string function, std::string smart_contract);

  /**
   * Return the Helena code for the "Uninitialized Storage Variable" vulnerability
   * @param function name of the function whose params are going to be checked
   * @param smart_contract name of smart contract that contains 'function'
   *  
   * @return Helena code
   */
    std::map<std::string, std::string> detectUninitializedStorageVariable(
    std::string variable, std::string function, std::string smart_contract);

  /**
   * Return the Helena code for the "Self Destruction" vulnerability
   * @param inputs a json file that holds the following params:
        * @param variable variable being tested
   * @return Helena code
   */
  std::map<std::string, std::string> detectSelfDestruction(
  std::string function,  std::string smart_contract, std::string rival_contract);
 
  /**
    * @brief Return the helena code that checks that a variable's value is always less than another variable/constant
    * 
    * @param variable 
    * @param rival_variable 
    * @param max_threshold 
    * @return Helena code
    */
  std::map<std::string, std::string> checkVariableAlwaysLessThan(std::string variable, std::string rival_variable, std::string max_threshold);

  /**
    * @brief Return the helena code that checks that a variable's value is always more than another variable/constant
    * 
    * @param variable 
    * @param rival_variable 
    * @param min_threshold 
    * @return Helena code of property to be verified and its propositions 
    */
  std::map<std::string, std::string> checkVariableAlwaysMoreThan(std::string variable, std::string rival_variable, std::string min_threshold);

  /**
    * @brief Return the helena code that checks that a variable's value is always equal another variable/constant
    * 
    * @param variable 
    * @param rival_variable 
    * @param constant 
    * @return Helena code of property to be verified and its propositions 
    */
  std::map<std::string, std::string> checkVariableAlwaysEqualTo(std::string variable, std::string rival_variable, std::string constant);

  /**
    * @brief 
    * 
    * @param function_name 
    * @param smart_contract
    * @return Return the helena code that checks if a function is always called
    */
  std::map<std::string, std::string> checkFunctionIsEventuallyCalled(std::string function_name, std::string smart_contract);

  /**
    * @brief
    * 
    * @param function_name 
    * @param smart_contract
    * @return Return the helena code that checks if a function is never called within a given context
    */
  std::map<std::string, std::string> checkFunctionIsNeverCalled(std::string function_name, std::string smart_contract);

  /**
    * @brief
    * 
    * @param function_name 
    * @param smart_contract
    * @return Return the helena code that checks if a function finshed execution within a given context
    */
  std::map<std::string, std::string> checkFunctionIsExecuted(std::string function_name, std::string smart_contract);

  /**
    * @brief 
    * 
    * @param function_name 
    * @param smart_contract
    * @param rival_function
    * @param rival_contract
    * @return Return the helena code that checks if a function B is called after function A call within a given context
    */
  std::map<std::string, std::string> checkIsSequentialCall(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract);

  /**
    * @brief 
    * 
    * @param function_name 
    * @param smart_contract
    * @param rival_function
    * @param rival_contract
    * @return Return the helena code that checks if a function B finishes execution after function A finished its execution within a given context
    */
  std::map<std::string, std::string> checkIsSequentialExecution(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract);

  /**
    * @brief 
    * 
    * @param function_name 
    * @param smart_contract
    * @param rival_function
    * @param rival_contract
    * @return Return the helena code that checks if a function B finishes execution after function A is called
    */
  std::map<std::string, std::string> checkCallFollowedByExec(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract);

  /**
    * @brief 
    * 
    * @param function_name 
    * @param smart_contract
    * @param rival_function
    * @param rival_contract
    * 
    * @return Return the helena code that checks if a function B is called after function A finishes execution
    */   
  std::map<std::string, std::string> checkExecFollowedByCall(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract);


  /**
    * @brief 
    * 
    * @param function parent function of sending statements
    * @param smart_contract smart contract that contains 'function'
    * 
    * 
    * @return Return output places of sending statements called in 'function' 
  */   
  std::list<std::string> get_sending_output_places(std::string function, std::string smart_contract);

  /**
    * @brief 
    * 
    * @param variable we only check for selection statements that use 'variable'
    * @param function parent function of selection statements
    * @param smart_contract parent contract of 'function'
    * 
    * @return Return output places of selection(if) statements that use 'variable' inside 'function' 
  */   
  std::list<std::string> get_selection_output_places(std::string variable, std::string function, std::string smart_contract);

  /**
    * @brief 
    * 
    * @param variable we only check for for_loop statements that use 'variable'
    * @param function parent function of for loop statements
    * @param smart_contract parent contract of 'function'
    * 
    * @return Return output places of for loop statements that use 'variable' inside 'function' 
  */   
  std::list<std::string> get_for_loops_output_places(std::string variable, std::string function, std::string smart_contract);

  /**
    * @brief 
    * 
    * @param variable we only check for while_loop statements that use 'variable'
    * @param function parent function of while loop statements
    * @param smart_contract parent contract of 'function'
    * 
    * @return Return output places of while loop statements that use 'variable' inside 'function' 
  */   
  std::list<std::string> get_while_loops_output_places(std::string variable,std::string function, std::string smart_contract);

  /**
    * @brief Return output places of require statements that use 'variable' inside 'function' 
    * 
    * @param variable we only check for require statements that use 'variable'
    * @param function parent function of require statements
    * @param smart_contract parent contract of 'function'
    * 
    * @return Return output places of require statements that use 'variable' inside 'function' 
  */   
  std::list<std::string> get_require_output_places(std::string variable,std::string function, std::string smart_contract);

  /**
    * @brief Return variables that represent the balance of 'smart contract' 
    * 
    * @param function look for variables inside 'function'
    * @param smart_contract parent contract of 'function'
    * 
    * @return Variables that represent the balance of 'smart contract'
  */   
  std::list<std::string> get_balance_variables(std::string function, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param function_name 
    * @param smart_contract
    * 
    * @return input places of 'function_name' called in 'smart contract'
  */    
  std::list<std::string> get_function_call_input_places(std::string function_name, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param function_name 
    * @param smart_contract
    * 
    * @return output places of 'function_name' called in 'smart contract'
  */    
  std::list<std::string> get_function_call_output_places(std::string function_name, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param function_name 
    * @param smart_contract
    * 
    * @return output places of all statements that use a timestamp inside 'function_name' of 'smart_contract'
  */    
  std::list<std::string> get_timestamp_places(std::string function_name, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param variable 
    * @param function
    * @param smart_contract
    * 
    * 
    * @return output places of statements that read 'variable' value inside 'function'
  */    
  std::list<std::string> get_read_output_places(std::string variable,std::string function, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param variable 
    * @param function
    * @param smart_contract
    * 
    * @return output places of statements that assign value to 'variable'
  */    
  std::list<std::string> get_write_output_places(std::string variable,std::string function, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param function
    * 
    * @return param places of all functions called inside 'function'
  */   
  std::list<std::string> get_function_call_param_places(std::string function, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param balance_variables
    * @param function
    * @param smart_contract
    * 
    * @return output places of all statements inside 'function' that test variables representing the balance of 'smart_contract'
  */   
  std::list<std::string> get_balance_variables_testing_output_places(std::list<std::string> balance_variables, std::string function, std::string smart_contract);

  /**
    * @brief  
    * 
    * @param balance_variables
    * @param function
    * 
    * @return output places of statements that assign values to variables representing the balance inside 'function'
  */   
  std::list<std::string> get_balance_variables_write_statements(std::list<std::string> balance_variables, std::string function, std::string smart_contract);
    

};

}  // namespace LTL2PROP

#endif  // LTLTTRANSLATOR_H_
//TODO: Complete Documentation