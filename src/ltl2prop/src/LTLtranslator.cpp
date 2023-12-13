#include "LTLtranslator.hpp"

#include <stddef.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

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

bool LTLTranslator::is_const_definition(const std::string& _name) const {
  return constDefinitions.find(_name) != constDefinitions.end();
}

std::string LTLTranslator::get_const_definition_value(
    const std::string& _name) {
  return is_const_definition(_name) ? constDefinitions[_name] : "";
}

bool LTLTranslator::is_global_variable(const std::string& _name) const {
  return global_variables.find(_name) != global_variables.end();
}

std::string LTLTranslator::get_global_variable_placetype(
    const std::string& _name) {
  return is_global_variable(_name) ? global_variables[_name] : "";
}

bool LTLTranslator::is_local_variable(const std::string& _name) const {
  return local_variables.find(_name) != local_variables.end();
}

std::string LTLTranslator::get_local_variable_placetype(
    const std::string& _name) {
  return is_local_variable(_name) ? local_variables[_name] : "";
}

std::map<std::string, std::string> LTLTranslator::translate() {
  // get the type of formula : general or specific
  std::string formula_type = formula_json.at("type");
  auto formula_params = formula_json.at("params");

  // parse a contract-specific formula (i.e., from template)
  if (formula_type == "specific") {
    return createVulMapFromFormula(formula_params.at("formula"));
  }

  // parse a general vulnerability formula
  if (formula_type == "general") {
    std::string vulnerability_name = formula_params.at("name");
    if (vulnerability_name == "Interger Overflow/Underflow") {
      auto inputs = formula_params.at("inputs");
      std::string min_threshold = inputs.at("min_threshold");
      std::string max_threshold = inputs.at("max_threshold");
      std::string variable = inputs.at("selected_variable");
      return createUnderOverFlowVul(min_threshold, max_threshold, variable);
    }
  }

  // throw an exception since the type cannot be handled
  throw std::runtime_error("formula type " + formula_type +
                           " is not handled by LTLTranslator");
}

std::map<std::string, std::string> LTLTranslator::createUnderOverFlowVul(
    const std::string& min_threshold, const std::string& max_threshold,
    const std::string& variable) {
  std::stringstream code;
  code << "const minThreshold = " + min_threshold + ";"
       << "\n"
       << "const maxThreshold = " + max_threshold + ""
       << "\n";
  code << "proposition oFut: ('" + variable + "' < minThreshold) | ('" +
              variable + "' > maxThreshold)"
       << "\n";
  code << "property outOfRange: G ( ! oFut );";
  return createVulMapFromFormula(code.str());
}

std::map<std::string, std::string> LTLTranslator::createVulMapFromFormula(
    const std::string& _formula) {
  std::vector<std::string> lines = split(_formula, "\n");

  // remove empty lines from Helena code
  for (auto& line : lines) {
    trim_ex(line);
    if (!line.empty()) {
      ltl_lines.emplace_back(line);
    }
  }

  // parse formula code
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

  // collect all the proposition in the formula
  std::stringstream prop_result;
  for (auto it = propositions.begin(); it != propositions.end(); ++it) {
    prop_result << (*it) << "\n";
  }

  std::map<std::string, std::string> result;
  std::cout << property_string << std::endl;
  result["propositions"] = prop_result.str();
  result["property"] = property_string;
  return result;
}

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

void LTLTranslator::handlePropositionDefinition() {
  std::string temp = *ptr_ltl_line;
  trim_ex(temp);
  std::string definition = split_ex(temp, " ", 2)[1];

  std::string prop_name =
      removeNoneAlnum(retrieve_string_element(definition, 0, ":"));
  std::string prop_def = retrieve_string_element(definition, 1, ":");

  std::string final_expression = analysePropositionExpression(prop_def);
  propositions.push_back("proposition " + prop_name + ":\n\t" +
                         final_expression + ";\n");
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
        throw std::runtime_error("operator " + op + " is not well-formed");
      }
    } else if (*it == OR_OP || *it == AND_OP) {
      if (opr.size() >= 2) {
        std::string first_opr = opr.back();
        opr.pop_back();
        std::string second_opr = opr.back();
        opr.pop_back();

        opr.push_back(second_opr + " " + op + " " + first_opr);
      } else {
        throw std::runtime_error("operator " + op + " is not well-formed");
      }
    } else if (*it == NOT_OP) {
      if (!opr.empty()) {
        std::string first_opr = opr.back();
        opr.pop_back();

        opr.push_back(op + " " + first_opr);
      } else {
        throw std::runtime_error("operator " + op + " is not well-formed");
      }
    } else if (*it == RUN_OP) {
      if (!opr.empty()) {
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
        throw std::runtime_error("operator " + op + " is not well-formed");
      }
    } else {
      opr.push_back(*it);
    }
  }

  if (opr.size() == 1) {
    return opr.back();
  }

  return "";  // error
}

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
      while (!opr_stack.empty() && precedence_of_op(els[cout]) <=
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

  while (!opr_stack.empty()) {
    opt_stack.push_back(opr_stack.back());
    opr_stack.pop_back();
  }

  return opt_stack;
}

std::vector<std::string> LTLTranslator::splitExpression(
    const std::string& _exp) {
  std::vector<std::string> result;
  std::vector<char> temp;
  int cout = 0;

  while (cout < _exp.length()) {
    if (_exp[cout] == '(' || _exp[cout] == ')' ||
        std::find(BooleanOperator.begin(), BooleanOperator.end(),
                  std::string(1, _exp[cout])) != BooleanOperator.end()) {
      if (!temp.empty()) {
        result.push_back(std::string(temp.begin(), temp.end()));
        temp.clear();
      }

      result.push_back(std::string(1, _exp[cout]));
    } else if (_exp[cout] == ' ' || _exp[cout] == '\n') {
      if (!temp.empty()) {
        result.push_back(std::string(temp.begin(), temp.end()));
        temp.clear();
      }
    } else if (_exp[cout] == '{') {
      if (!temp.empty()) {
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

  if (!temp.empty()) {
    result.push_back(std::string(temp.begin(), temp.end()));
    temp.clear();
  }

  return result;
}

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
      "ltl property " + property_name + ":\n\t" + property.str() + "\n";
}

std::string LTLTranslator::handleNoNamePropositionDefinition(
    const std::string& _def) {
  std::string proposition_name =
      "proposition_number_" + std::to_string(current_noname_proposition);
  current_noname_proposition++;

  std::string expression = substr_by_edge(_def, "{", "}");
  std::string final_expression = analysePropositionExpression(expression);

  propositions.push_back("proposition " + proposition_name + ":\n\t" +
                         final_expression + ";\n");
  return proposition_name;
}

std::vector<std::string> LTLTranslator::getListVariableFromFormula(
    const std::string& _formula) {
  std::vector<std::string> lines = split(_formula, "\n");
  std::list<std::string> temp_ltl_lines;

  // remove empty lines from the formula code
  for (auto& line : lines) {
    trim_ex(line);
    if (!line.empty()) {
      temp_ltl_lines.emplace_back(line);
    }
  }

  std::vector<std::string> ret;
  std::list<std::string>::iterator temp_ptr_ltl_line = temp_ltl_lines.begin();
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

}  // namespace LTL2PROP