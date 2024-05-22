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
  struct AssignmentStatement{
     std::string variable;
     std::string input_place;
     std::string parent;
     std::string output_place;
	std::list<std::string> RHV;
	bool	timestamp;
  };

  struct FunctionCallStatement{
     std::string function_name;
     std::string input_place;
     std::string parent;
     std::string output_place;
  };

  struct BranchingStatement{
     std::string variable;
     std::string input_place;
     std::string parent;
     std::string output_place;
	bool	timestamp;
  };
    struct SendingStatement{
     std::string variable;
     std::string input_place;
     std::string parent;
     std::string output_place;
	bool	timestamp;
  };

  std::map<std::string, std::string> result = { {"property", ""}, {"propositions", ""}};
  nlohmann::json formula_json;
  nlohmann::json statements;
  std::map<std::string, std::string> local_variables;
  std::list<std::string> global_variables;
  std::list<AssignmentStatement> assignments;
  std::list<SendingStatement> sendings;
  std::list<BranchingStatement> branchings;
  std::list<FunctionCallStatement> function_calls;



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
    IsCalled,
    IsNeverCalled,
    IsExecuted,
    IsNeverExecuted,
    SequentialCall,
    InfiniteLoop,
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
   * @param inputs a json file that holds the following params:
        * 1. min_threshold minimum threshold value
        * 2. max_threshold maximum threshold value
        * 3. variable variable being tested
   * @return Helena code
   */
    std::map<std::string, std::string> detectUnderOverFlowVul(
      nlohmann::json inputs);
      
  /**
   * Return the Helena code for the "Reentrancy" vulnerability
   * @param inputs a json file that holds the following params:
   * if contract is totally free:     
        * variable: variable being tested
   * if rival contract is available:
        * rival contract:   
   * @return Helena code
   */
    std::map<std::string, std::string> detectReentrancy(
    nlohmann::json inputs);

    

  /**
   * Return the Helena code for the "TimestampDestruction" vulnerability
   * @param inputs a json file that holds the following params:
   * @return Helena code
   */
    std::map<std::string, std::string> detectTimestampDependance(
    nlohmann::json inputs);

  /**
   * Return the Helena code for the "Skip Empty String Literal" vulnerability
   * @param inputs a json file that holds the following params:
   * @return Helena code
   */
    std::map<std::string, std::string> detectSkipEmptyStringLiteral(
    nlohmann::json inputs);

  /**
   * Return the Helena code for the "Uninitialized Storage Variable" vulnerability
   * @param inputs a json file that holds the following params:
   * @return Helena code
   */
    std::map<std::string, std::string> detectUninitializedStorageVariable(
    nlohmann::json inputs);

  /**
   * Return the Helena code for the "Self Destruction" vulnerability
   * @param inputs a json file that holds the following params:
        * @param variable variable being tested
   * @return Helena code
   */
    std::map<std::string, std::string> detectSelfDestruction(
    nlohmann::json inputs);
 

    std::map<std::string, std::string> checkAlwaysLessThan(nlohmann::json inputs);

    std::map<std::string, std::string> checkAlwaysMoreThan(nlohmann::json inputs);

    std::map<std::string, std::string> checkAlwaysEqual(nlohmann::json inputs);

    std::map<std::string, std::string> checkIsCalled(nlohmann::json inputs);

    std::map<std::string, std::string> checkIsNeverCalled(nlohmann::json inputs);

    std::map<std::string, std::string> checkIsExecuted(nlohmann::json inputs);

    std::map<std::string, std::string> checkIsNeverExecuted(nlohmann::json inputs);

    std::map<std::string, std::string> checkIsSequential(nlohmann::json inputs);

    std::map<std::string, std::string> checkIsInfinite(nlohmann::json inputs);



    std::string get_sending_output_place(std::string variable);
    std::string get_assignment_output_place(std::string variable);
    std::string get_branching_output_place(std::string variable);
    std::string get_function_call_input_place(std::string function_name);
    std::string get_function_call_output_place(std::string function_name);
    std::list<std::string> get_timestamp_places();
    std::string get_read_output_place(std::string variable);
    bool timestamp_exists();
    

};

}  // namespace LTL2PROP

#endif  // LTLTTRANSLATOR_H_
