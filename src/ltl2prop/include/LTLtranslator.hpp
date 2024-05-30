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
				std::list<std::string> RHV;
				bool timestamp;
  };

  std::map<std::string, std::string> result = { {"property", ""}, {"propositions", ""}};
  nlohmann::json formula_json;
  nlohmann::json statement_list;
  std::map<std::string, std::string> local_variables;
  std::list<std::string> global_variables;
  std::list<Statement> assignments,
   sendings, selections, function_calls,
  variable_declarations, returnings, requirements,
   for_loops, while_loops;







  enum vulnerabilities {
    IntegerOverflowUnderflow,
    Reentrancy,
    TimestampDependence,
    SelfDestruction,
    SkipEmptyStringLiteral,
    UninitializedStorageVariable,
    AlwaysLessThan,
    AlwaysMoreThan,
    AlwaysEqual,
    IsAlwaysCalled,
    IsNeverCalled,
    IsExecuted,
    SequentialCall,
};

  vulnerabilities getVulnerability(std::string vulnerability);

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
    std::map<std::string, std::string> detectUnderOverFlowVul(std::string variable, std::string min_threshold, std::string max_threshold);
      
  /**
   * Return the Helena code for the "Reentrancy" vulnerability
   * @param inputs a json file that holds the following params:
   * if contract is totally free:     
        @param variable: variable being tested
        @param function: function used for sending
   * if rival contract is available:
        @param variable: variable being tested
        @param rival_contract: rival contract for second formula   
   * @return Helena code
   */
    std::map<std::string, std::string> detectReentrancy(
    std::string variable, std::string function, std::string rival_contract);

    

  /**
   * Return the Helena code for the "TimestampDestruction" vulnerability
   * @return Helena code
   */
    std::map<std::string, std::string> detectTimestampDependance();

  /**
   * Return the Helena code for the "Skip Empty String Literal" vulnerability
   * @param function name of the function whose params are going to be checked 
   * @return Helena code
   */
    std::map<std::string, std::string> detectSkipEmptyStringLiteral(
    std::string function);

  /**
   * Return the Helena code for the "Uninitialized Storage Variable" vulnerability
   * @param inputs a json file that holds the following params:
   * @return Helena code
   */
    std::map<std::string, std::string> detectUninitializedStorageVariable(
    std::string variable);

  /**
   * Return the Helena code for the "Self Destruction" vulnerability
   * @param inputs a json file that holds the following params:
        * @param variable variable being tested
   * @return Helena code
   */
    std::map<std::string, std::string> detectSelfDestruction(
    std::string variable, std::string function,  std::string smart_contract, std::string rival_contract);
 
     /**
      * @brief Return the helena code that checks that a variable's value is always less than another variable/constant
      * 
      * @param variable 
      * @param rival_variable 
      * @param max_threshold 
      * @return Helena code
      */
    std::map<std::string, std::string> checkAlwaysLessThan(std::string variable, std::string rival_variable, std::string max_threshold);
     /**
      * @brief Return the helena code that checks that a variable's value is always more than another variable/constant
      * 
      * @param variable 
      * @param rival_variable 
      * @param min_threshold 
      * @return Helena code of property to be verified and its propositions 
      */
    std::map<std::string, std::string> checkAlwaysMoreThan(std::string variable, std::string rival_variable, std::string min_threshold);

     /**
      * @brief Return the helena code that checks that a variable's value is always equal another variable/constant
      * 
      * @param variable 
      * @param rival_variable 
      * @param constant 
      * @return Helena code of property to be verified and its propositions 
      */
    std::map<std::string, std::string> checkAlwaysEqual(std::string variable, std::string rival_variable, std::string constant);

     /**
      * @brief Return the helena code that checks if a function is always called.
      * 
      * @param function_name 
      * @return Helena code of property to be verified and its propositions
      */
    std::map<std::string, std::string> checkIsAlwaysCalled(std::string function_name, std::string smart_contract);

     /**
      * @brief Return the helena code that checks if a function is never called within a given context
      * 
      * @param function_name 
      * @return Helena code of property to be verified and its propositions
      */
    std::map<std::string, std::string> checkIsNeverCalled(std::string function_name, std::string smart_contract);

     /**
      * @brief Return the helena code that checks if a function finshed execution within a given context
      * 
      * @param function_name 
      * @return Helena code of property to be verified and its propositions
      */
    std::map<std::string, std::string> checkIsExecuted(std::string function_name, std::string smart_contract);

     /**
      * @brief Return the helena code that checks if a function B is called after function A within a given context
      * 
      * @param function_name 
      * @return Helena code of property to be verified and its propositions
      */
    std::map<std::string, std::string> checkIsSequential(std::string function_name, std::string smart_contract, std::string rival_function, std::string rival_contract);




    std::list<std::string> get_sending_output_places(std::string function);
    std::list<std::string> LTLTranslator::get_assignment_output_places(std::string variable, std::string function);
    std::list<std::string> LTLTranslator::get_selection_output_places(std::string variable, std::string function, std::string smart_contract);
    std::list<std::string> LTLTranslator::get_for_loops_output_places(std::string variable, std::string function, std::string smart_contract);
    std::list<std::string> LTLTranslator::get_while_loops_output_places(std::string variable,std::string function, std::string smart_contract);
    std::list<std::string> LTLTranslator::get_require_output_places(std::string variable,std::string function, std::string smart_contract);

    //TODO: add require, for loops and while loops output places functions
    std::string get_function_call_input_place(std::string function_name, std::string smart_contract);
    std::string get_function_call_output_place(std::string function_name, std::string smart_contract);
    std::list<std::string> get_timestamp_places();
    std::list<std::string> get_read_output_places(std::string variable);
    std::list<std::string> get_write_output_places(std::string variable);
    bool timestamp_exists();
    

};

}  // namespace LTL2PROP

#endif  // LTLTTRANSLATOR_H_
//TODO: Complete Documentation