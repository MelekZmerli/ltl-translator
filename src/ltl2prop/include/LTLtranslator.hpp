#ifndef LTLTRANSLATOR_H_
#define LTLTRANSLATOR_H_

#include <json.hpp>
#include <list>
#include <map>
#include <string>
#include <vector>

namespace LTL2PROP {

const std::string CONST_STRING = "const";
const std::string PROPOSITION_STRING = "proposition";
const std::string PROPERTY_STRING = "property";
const std::list<std::string> TokensDefine = {CONST_STRING, PROPOSITION_STRING,
                                             PROPERTY_STRING};

const std::string GREATER_THAN = ">";
const std::string GREATER_THAN_OR_EQUAL_TO = ">=";
const std::string LESS_THAN = "<";
const std::string LESS_THAN_OR_EQUAL_TO = "<=";
const std::string NOT_EQUAL_TO = "!=";
const std::string EQUAL_TO = "==";
const std::list<std::string> ComparisonOperator = {
    GREATER_THAN, GREATER_THAN_OR_EQUAL_TO,
    LESS_THAN,    LESS_THAN_OR_EQUAL_TO,
    NOT_EQUAL_TO, EQUAL_TO};

const std::string OR_OP = "|";
const std::string AND_OP = "&";
const std::string NOT_OP = "!";
const std::string OPEN_PARENTHESES = "(";
const std::string CLOSE_PARENTHESES = ")";
const std::list<std::string> BooleanOperator = {
    OR_OP,
    AND_OP,
    NOT_OP,
};

const std::string GLOBAL_OP = "G";
const std::string FINALLY_OP = "F";
const std::string UNTIL_OP = "U";
const std::string RUN_OP = "run";
const std::string EXEC_OP = "exec";
const std::list<std::string> LTLOperator = {GLOBAL_OP, FINALLY_OP, UNTIL_OP,
                                            RUN_OP, EXEC_OP};

const std::string OR_OP_PROP = "or";
const std::string AND_OP_PROP = "and";
const std::string NOT_OP_PROP = "not";
const std::string GLOBAL_OP_PROP = "[]";
const std::string FINALLY_OP_PROP = "<>";
const std::string UNTIL_OP_PROP = "until";

const std::string PROPOSITION_AREA = "proposition";

/**
 * Return the precedence level of an operator
 *
 * @param _op operator
 * @return precedence level
 */
int precedence_of_op(const std::string& _op);

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
  nlohmann::json formula_json;
  std::map<std::string, std::string> MappingOp;
  std::list<std::string> ltl_lines;
  std::list<std::string>::iterator ptr_ltl_line;
  std::map<std::string, std::string> constDefinitions;
  std::map<std::string, std::string> local_variables;
  std::map<std::string, std::string> global_variables;
  std::vector<std::string> propositions;
  std::string property_string;
  int current_noname_proposition = 1;

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
   * Return the place modeling the global variable _name
   *
   * @param _name global variable
   * @return name of the place
   */
  std::string get_global_variable_placetype(const std::string& _name);

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
   * Return the Helena code for the "Interger Overflow/Underflow" vulnerability
   *
   * @param min_threshold minimum threshold value
   * @param max_threshold maximum threshold value
   * @param variable variable being tested
   * @return Helena code
   */
  std::map<std::string, std::string> createUnderOverFlowVul(
      const std::string& min_threshold, const std::string& max_threshold,
      const std::string& variable);

  /**
   * Return the Helena code from an formula
   *
   * @param _formula Helena formula
   * @return mapping of propositions and the property
   */
  std::map<std::string, std::string> createVulMapFromFormula(
      const std::string& _formula);

  /**
   * Parse const definitions from Helena code
   */
  void handleConstDefinition();

  /**
   * Parse proposition definitions from Helena code
   */
  void handlePropositionDefinition();

  /**
   * Parse the expression inside a proposition from Helena code
   *
   * TODO: refactor since it's very complex
   *
   * @param _exp expression code
   * @return parsed expression
   */
  std::string analysePropositionExpression(const std::string& _exp);

  /**
   * Convert an infix expression into a postfix one
   *
   * @param _exp expression code
   * @return postfix expression code
   */
  static std::vector<std::string> infixToPostfixExpression(
      const std::string& _exp);

  /**
   * Split an expression into a list its elements
   *
   * Example:
   *
   * ```cpp
   *  std::string input = "(F(is_valid))";
   *  std::vector<std::string> out = splitExpression(input);
   *  output = {"(","F","(","is_valid",")",")"
   * ```
   *
   * @param _exp expression
   * @return list of elements
   */
  static std::vector<std::string> splitExpression(const std::string& _exp);

  /**
   * Parse property definitions from Helena code
   */
  void handlePropertyDefinition();

  /**
   * Parse an anonymous proposition
   *
   * @param _def expression containing the proposition
   * @return Helena code
   */
  std::string handleNoNamePropositionDefinition(const std::string& _def);
};

}  // namespace LTL2PROP

#endif  // LTLTTRANSLATOR_H_
