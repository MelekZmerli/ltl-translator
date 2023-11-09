#include "LTLtranslator.hpp"

#include <stddef.h>

#include <iostream>
#include <memory>
#include <sstream>

#include "json.hpp"
#include "utils.hpp"

namespace LTL2PROP {

int precedence_of_op(const std::string& _op) {
  if (_op == NOT_OP || _op == GLOBAL_OP || _op == FINALLY_OP || _op == RUN_OP ||
      _op == EXEC_OP) {
    return 2;
  }

  if (_op == OR_OP || _op == AND_OP || _op == UNTIL_OP ||
      std::find(ComparisonOperator.begin(), ComparisonOperator.end(), _op) !=
          ComparisonOperator.end()) {
    return 1;
  }

  return 0;
}

LTLTranslator::LTLTranslator(const nlohmann::json& lna_json,
                             const nlohmann::json& ltl_json) {
  formula_json = ltl_json;
  handleVariable(lna_json);
  createMap();
}

void LTLTranslator::createMap() {
  MappingOp[OR_OP] = OR_OP_PROP;
  MappingOp[AND_OP] = AND_OP_PROP;
  MappingOp[NOT_OP] = NOT_OP_PROP;
  MappingOp[GLOBAL_OP] = GLOBAL_OP_PROP;
  MappingOp[FINALLY_OP] = FINALLY_OP_PROP;
  MappingOp[UNTIL_OP] = UNTIL_OP_PROP;
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
}

/** Check if _name is defined as const
 */
bool LTLTranslator::is_const_definition(const std::string& _name) {
  if (constDefinitions.find(_name) != constDefinitions.end()) {
    return true;
  }
  return false;
}
/** Get value of _name (_name is defined as const)
 */
std::string LTLTranslator::get_const_definition_value(
    const std::string& _name) {
  if (is_const_definition(_name)) {
    return constDefinitions[_name];
  }
  return "";
}
/** Check if _name is  global variable
 */
bool LTLTranslator::is_global_variable(const std::string& _name) {
  if (global_variables.find(_name) != global_variables.end()) {
    return true;
  }
  return false;
}
/** Get global variable placetype by input
 */
std::string LTLTranslator::get_global_variable_placetype(
    const std::string& _name) {
  if (is_global_variable(_name)) {
    return global_variables[_name];
  }
  return "";
}
/** Check if _name is local variable
 */
bool LTLTranslator::is_local_variable(const std::string& _name) {
  if (local_variables.find(_name) != local_variables.end()) {
    return true;
  }
  return false;
}
/** Get local variable placetype by input
 */
std::string LTLTranslator::get_local_variable_placetype(
    const std::string& _name) {
  if (is_local_variable(_name)) {
    return local_variables[_name];
  }
  return "";
}

/** Read ltl,lna,json file as input and output lna and prop.lna file
 */
std::map<std::string, std::string> LTLTranslator::translate() {
  std::string ltl_type = formula_json.at("type");
  auto ltl_param = formula_json.at("params");
  if (ltl_type == "general") {
    std::string ltl_name = ltl_param.at("name");
    if (ltl_name == "under_over_flow") {
      auto inputs = ltl_param.at("inputs");
      std::string min_threshold = inputs.at("min_threshold");
      std::string max_threshold = inputs.at("max_threshold");
      std::string variable = inputs.at("selected_variable");
      return createUnderOverFlowVul(min_threshold, max_threshold, variable);
    }
  } else if (ltl_type == "specific") {
    return createVulFileFromFormula(ltl_param.at("formula"));
  }
}

std::map<std::string, std::string> LTLTranslator::createUnderOverFlowVul(
    const std::string& min_threshold, const std::string& max_threshold,
    const std::string& variable) {
  std::stringstream _vul;
  _vul << "const minThreshold = " + min_threshold + ";"
       << "\n"
       << "const maxThreshold = " + max_threshold + ""
       << "\n";
  _vul << "proposition oFut: ('" + variable + "' < minThreshold) | ('" +
              variable + "' > maxThreshold);"
       << "\n";
  _vul << "property outOfRange: G ( ! oFut );";
  return createVulFileFromFormula(_vul.str());
}

std::map<std::string, std::string> LTLTranslator::createVulFileFromFormula(
    std::string _formula) {
  std::vector<std::string> lines = split(_formula, "\n");

  for (size_t i = 0; i < lines.size(); i++) {
    std::string line = lines[i];
    if (!line.empty()) {
      std::string temp = std::string(line);
      trim_ex(temp);
      if (temp.length() > 0)
        ltl_lines.emplace_back(line);
    }
  }
  ptr_ltl_line = ltl_lines.begin();

  while (ptr_ltl_line != ltl_lines.end()) {
    std::string keyword = retrieve_string_element(*ptr_ltl_line, 0, " ");
    if (std::find(TokensDefine.begin(), TokensDefine.end(), keyword) !=
        TokensDefine.end()) {
      if (keyword == CONST_STRING) {
        handleConstDefinition();
      } else if (keyword == PROPOSITION_STRING) {
        handlePropositionDefinition();
      } else if (keyword == PROPERTY_STRING) {
        handlePropertyDefinition();
      }
    }
    ++ptr_ltl_line;
  }

  std::stringstream prop_result;
  for (auto it = propositions.begin(); it != propositions.end(); ++it) {
    prop_result << (*it) << "\n";
  }

  std::map<std::string, std::string> result;
  result["propositions"] = prop_result.str();
  result["property"] = property_string;
  return result;
}

std::vector<std::string> LTLTranslator::getListVariableFromFormula(
    const std::string& _formula) {
  std::vector<std::string> lines = split(_formula, "\n");
  std::list<std::string> temp_ltl_lines;

  for (size_t i = 0; i < lines.size(); i++) {
    std::string line = lines[i];
    if (!line.empty()) {
      std::string temp = std::string(line);
      trim_ex(temp);
      if (temp.length() > 0)
        temp_ltl_lines.emplace_back(line);
    }
  }
  std::list<std::string>::iterator temp_ptr_ltl_line = temp_ltl_lines.begin();

  std::vector<std::string> ret;
  while (temp_ptr_ltl_line != temp_ltl_lines.end()) {
    std::string keyword = retrieve_string_element(*temp_ptr_ltl_line, 0, " ");
    if (std::find(TokensDefine.begin(), TokensDefine.end(), keyword) !=
        TokensDefine.end()) {
      if (keyword == PROPOSITION_STRING || keyword == PROPERTY_STRING) {
        std::string prop_def =
            retrieve_string_element(*temp_ptr_ltl_line, 1, ":");
        std::vector<std::string> expression = splitExpression(prop_def);
        for (auto it = expression.begin(); it != expression.end(); ++it) {
          std::string op = *it;
          if (op[0] == '\'') {
            ret.push_back(op);
          }
        }
      }
    }
    ++temp_ptr_ltl_line;
  }
  return ret;
}

/** Analyse const definition
 */
void LTLTranslator::handleConstDefinition() {
  std::string temp = *ptr_ltl_line;
  trim_ex(temp);
  std::string definition = split_ex(temp, " ", 2)[1];

  std::string variable =
      removeNoneAlnum(retrieve_string_element(definition, 0, "="));
  std::string value =
      removeNoneAlnum(retrieve_string_element(definition, 1, "="));

  constDefinitions[variable] = value;
}

/** Analyse proposition definition
 */
void LTLTranslator::handlePropositionDefinition() {
  std::string temp = *ptr_ltl_line;
  trim_ex(temp);
  std::string definition = split_ex(temp, " ", 2)[1];

  std::string prop_name =
      removeNoneAlnum(retrieve_string_element(definition, 0, ":"));
  std::string prop_def = retrieve_string_element(definition, 1, ":");

  std::string finnal_expression = analysePropositionExpression(prop_def);

  propositions.push_back("proposition " + prop_name + ":\n\t" +
                         finnal_expression + ";\n");
}

std::string LTLTranslator::handleNoNamePropositionDefinition(
    const std::string& _def) {
  std::string proposition_name =
      "proposition_number_" + std::to_string(current_noname_proposition);
  current_noname_proposition++;

  std::string expression = substr_by_edge(_def, "{", "}");
  std::string finnal_expression = analysePropositionExpression(expression);

  propositions.push_back("proposition " + proposition_name + ":\n\t" +
                         finnal_expression + ";\n");
  return proposition_name;
}

std::string LTLTranslator::analysePropositionExpression(
    const std::string& _exp) {
  std::vector<std::string> expression = infixToPostfixExpression(_exp);

  std::vector<std::string> opr;
  for (auto it = expression.begin(); it != expression.end(); ++it) {
    std::string op = *it;

    if (MappingOp.find(op) != MappingOp.end()) {
      op = MappingOp[op];
    }

    if (std::find(ComparisonOperator.begin(), ComparisonOperator.end(), *it) !=
        ComparisonOperator.end()) {
      if (opr.size() >= 2) {
        std::stringstream temp_exp;
        std::string first_opr = opr.back();
        opr.pop_back();
        std::string second_opr = opr.back();
        opr.pop_back();

        if (first_opr.find("'") != std::string::npos) {
          std::string first_opr_name = substr_by_edge(first_opr, "'", "'");
          trim_ex(first_opr_name);
          std::string first_v;
          if (is_global_variable(first_opr_name)) {
            std::string v = get_global_variable_placetype(first_opr_name);
            temp_exp << "exists (t1 in S | ";
            first_v = "(t1->1)." + split(v, ".")[1];
          } else if (is_local_variable(first_opr_name)) {
            std::string v = get_local_variable_placetype(first_opr_name);
            temp_exp << "exists (t1 in " + v + " | ";
            first_v = "t1->1";
          }

          if (second_opr.find("'") != std::string::npos) {
            std::string second_opr_name = substr_by_edge(second_opr, "'", "'");
            trim_ex(second_opr);

            if (is_global_variable(second_opr_name)) {
              std::string v = get_global_variable_placetype(second_opr_name);
              temp_exp << "exists (t2 in S | (t2->1)." << split(v, ".")[1]
                       << " " + op << " " + first_v << "))";
            } else if (is_local_variable(second_opr_name)) {
              std::string v = get_local_variable_placetype(second_opr_name);
              temp_exp << "exists (t in " + v + " | t->1"
                       << " " + op << " " + first_v << "))";
            }
          } else if (is_const_definition(second_opr)) {
            temp_exp << get_const_definition_value(second_opr) << " " + op
                     << " " + first_v << ")";
          } else {
            temp_exp << second_opr << " " + op << " " + first_v << ")";
          }
        } else {
          if (is_const_definition(first_opr)) {
            first_opr = get_const_definition_value(first_opr);
          }

          if (second_opr.find("'") != std::string::npos) {
            std::string second_opr_name = substr_by_edge(second_opr, "'", "'");
            trim_ex(second_opr);

            if (is_global_variable(second_opr_name)) {
              std::string v = get_global_variable_placetype(second_opr_name);
              temp_exp << "exists (t2 in S | (t2->1)." << split(v, ".")[1]
                       << " " + op << " " + first_opr << ")";
            } else if (is_local_variable(second_opr_name)) {
              std::string v = get_local_variable_placetype(second_opr_name);
              temp_exp << "exists (t in " + v + " | t->1"
                       << " " + op << " " + first_opr << ")";
            }
          } else if (is_const_definition(second_opr)) {
            temp_exp << get_const_definition_value(second_opr) << " " + op
                     << " " + first_opr << ")";
          } else {
            temp_exp << second_opr << " " + op << " " + first_opr << ")";
          }
        }
        opr.push_back(temp_exp.str());
      } else {
        // error
      }

    } else if (*it == OR_OP || *it == AND_OP) {
      if (opr.size() >= 2) {
        std::string first_opr = opr.back();
        opr.pop_back();
        std::string second_opr = opr.back();
        opr.pop_back();

        opr.push_back(second_opr + " " + op + " " + first_opr);
      } else {
        // error
      }
    } else if (*it == NOT_OP) {
      if (opr.size() >= 1) {
        std::string first_opr = opr.back();
        opr.pop_back();

        opr.push_back(op + " " + first_opr);
      } else {
        // error
      }
    } else if (*it == RUN_OP) {
      if (opr.size() >= 1) {
        std::string first_opr = opr.back();
        opr.pop_back();

        std::string opr_type;
        std::vector<std::string> temp_split = split_ex(first_opr, ".", 2);
        if (temp_split.size() == 2) {
          opr_type = temp_split[1];
        } else {
          opr_type = "var";
        }

        std::string opr_name = substr_by_edge(first_opr, "'", "'");
        std::string temp_exp;

        if (opr_type == "var") {
          if (is_local_variable(opr_name)) {
            std::string v = get_local_variable_placetype(opr_name);
            temp_exp += v + "'card > 0";
          }
        } else if (opr_type == "func") {
          temp_exp += opr_name + "_cflow" + "'card > 0";
        }
        opr.push_back(temp_exp);
      } else {
        // error
      }
    } else {
      opr.push_back(*it);
    }
  }
  if (opr.size() == 1) {
    return opr.back();
  } else {
    // error
    return "";
  }
}
/** Analyse property definition
 */
void LTLTranslator::handlePropertyDefinition() {
  std::string temp = *ptr_ltl_line;
  trim_ex(temp);
  std::string definition = split_ex(temp, " ", 2)[1];

  std::string property_name = removeNoneAlnum(split_ex(definition, ":", 2)[0]);
  std::string property_def = split_ex(definition, ":", 2)[1];
  std::vector<std::string> els = splitExpression(property_def);

  std::stringstream property;
  for (auto it = els.begin(); it != els.end(); ++it) {
    if ((*it).find("{") != std::string::npos) {
      std::string prop_name = handleNoNamePropositionDefinition(*it);
      property << prop_name << " ";
    } else if (MappingOp.find(*it) != MappingOp.end()) {
      property << MappingOp[*it] << " ";
    } else {
      property << *it << " ";
    }
  }

  property_string =
      "ltl property " + property_name + ":\n\t" + property.str() + ";\n";
}
/** Convert proposition expression to proposition in lna file
 */
std::vector<std::string> LTLTranslator::infixToPostfixExpression(
    const std::string& _exp) {
  std::vector<std::string> els = splitExpression(_exp);
  std::vector<std::string> opt_stack;
  std::vector<std::string> opr_stack;
  int cout = 0;

  while (cout < els.size()) {
    if (els[cout] == OPEN_PARENTHESES) {
      opr_stack.push_back(els[cout]);
    } else if (els[cout] == CLOSE_PARENTHESES) {
      while (opr_stack.back() != OPEN_PARENTHESES) {
        opt_stack.push_back(opr_stack.back());
        opr_stack.pop_back();
      }
      opr_stack.pop_back();
    } else if (std::find(ComparisonOperator.begin(), ComparisonOperator.end(),
                         els[cout]) != ComparisonOperator.end() ||
               std::find(BooleanOperator.begin(), BooleanOperator.end(),
                         els[cout]) != BooleanOperator.end() ||
               std::find(LTLOperator.begin(), LTLOperator.end(), els[cout]) !=
                   LTLOperator.end()) {
      while (opr_stack.size() > 0 && precedence_of_op(els[cout]) <=
                                         precedence_of_op(opr_stack.back())) {
        opt_stack.push_back(opr_stack.back());
        opr_stack.pop_back();
      }
      opr_stack.push_back(els[cout]);
    } else {
      opt_stack.push_back(els[cout]);
    }
    cout++;
  }
  while (opr_stack.size() > 0) {
    opt_stack.push_back(opr_stack.back());
    opr_stack.pop_back();
  }

  return opt_stack;
}

/** Split expression string into list of element
 *      example:
 *          std::string input = "(F(is_valid))";
 *          std::vector<std::string> out = splitExpression(input);
 *          output = {"(","F","(","is_valid",")",")"}
 */
std::vector<std::string> LTLTranslator::splitExpression(
    const std::string& _exp) {
  std::vector<std::string> result;
  std::vector<char> temp;
  int cout = 0;

  while (cout < _exp.length()) {
    if (_exp[cout] == '(' || _exp[cout] == ')' ||
        std::find(BooleanOperator.begin(), BooleanOperator.end(),
                  std::string(1, _exp[cout])) != BooleanOperator.end()) {
      if (temp.size() > 0) {
        result.push_back(std::string(temp.begin(), temp.end()));
        temp.clear();
      }

      result.push_back(std::string(1, _exp[cout]));
    } else if (_exp[cout] == ' ' || _exp[cout] == '\n') {
      if (temp.size() > 0) {
        result.push_back(std::string(temp.begin(), temp.end()));
        temp.clear();
      }
    } else if (_exp[cout] == '{') {
      if (temp.size() > 0) {
        result.push_back(std::string(temp.begin(), temp.end()));
        temp.clear();
      }

      while (_exp[cout] != '}' && cout < _exp.length()) {
        temp.push_back(_exp[cout]);
        cout++;
      }

      if (cout < _exp.length()) {
        temp.push_back('}');
        result.push_back(std::string(temp.begin(), temp.end()));
        temp.clear();
      }

    } else {
      temp.push_back(_exp[cout]);
    }
    cout++;
  }

  if (temp.size() > 0) {
    result.push_back(std::string(temp.begin(), temp.end()));
    temp.clear();
  }

  return result;
}

}  // namespace LTL2PROP