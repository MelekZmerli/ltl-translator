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

  std::map<std::string, std::string> translate();

  std::map<std::string, std::string> createUnderOverFlowVul(
      const std::string& min_threshold, const std::string& max_threshold,
      const std::string& variable);
  std::map<std::string, std::string> createVulFileFromFormula(
      std::string _formula);

  void handleConstDefinition();
  void handlePropositionDefinition();

  void handlePropertyDefinition();

  static std::vector<std::string> infixToPostfixExpression(
      const std::string& _exp);
  static std::vector<std::string> splitExpression(const std::string& _exp);

  std::string handleNoNamePropositionDefinition(const std::string& _def);

  std::string analysePropositionExpression(const std::string& _exp);
  bool is_const_definition(const std::string& _name);
  std::string get_const_definition_value(const std::string& _name);

  bool is_global_variable(const std::string& _name);
  std::string get_global_variable_placetype(const std::string& _name);

  bool is_local_variable(const std::string& _name);
  std::string get_local_variable_placetype(const std::string& _name);

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
};

}  // namespace LTL2PROP

#endif  // LTLTTRANSLATOR_H_
