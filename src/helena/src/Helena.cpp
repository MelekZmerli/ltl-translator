#include "Helena.hpp"

#include <algorithm>

namespace HELENA {

/******************************************************************************
 * Implementation of the LnaNode Class
 *****************************************************************************/

LnaNodeType LnaNode::get_node_type() const {
  return node_type;
}

size_t LnaNode::size() const {
  return lna_nodes.size();
}

void LnaNode::append_sub_node(const LnaNodePtr& _node) {
  lna_nodes.push_back(_node);
}

void LnaNode::delete_sub_node(const unsigned int& x) {
  lna_nodes.erase(lna_nodes.begin() + x);
}

void LnaNode::update_sub_node(const unsigned int& x, const LnaNodePtr _node) {
  lna_nodes[x] = _node;
}

LnaNodePtr LnaNode::get_sub_node(const unsigned int& x) const {
  return lna_nodes[x];
}

/******************************************************************************
 * Implementation of the ParameterNode Class
 *****************************************************************************/

std::string ParameterNode::source_code() {
  std::string result = name + " := " + number;
  return result;
}

void ParameterNode::set_name(const std::string& _name) {
  name = _name;
}

std::string ParameterNode::get_name() const {
  return name;
}

void ParameterNode::set_number(const std::string& _number) {
  number = _number;
}

std::string ParameterNode::get_number() const {
  return number;
}

/******************************************************************************
 * Implementation of the NetNode Class
 *****************************************************************************/

std::string NetNode::source_code() {
  std::stringstream result;
  result << name;

  if (!param_nodes.empty()) {
    result << "(";
    for (auto it = param_nodes.begin(); it != param_nodes.end(); ++it) {
      result << (*it)->source_code();
      if (it != param_nodes.end() - 1) {
        result << ", ";
      }
    }
    result << ")";
  }

  result << " {\n";
  for (auto it = lna_nodes.begin(); it != lna_nodes.end(); ++it) {
    result << (*it)->source_code();
  }

  result << "\n}";
  return result.str();
}

void NetNode::set_name(const std::string& _name) {
  name = _name;
}

std::string NetNode::get_name() const {
  return name;
}

void NetNode::add_parameter(const ParameterNodePtr& _node) {
  param_nodes.push_back(_node);
}

void NetNode::add_member(const LnaNodePtr& _node) {
  append_sub_node(_node);
}

void NetNode::delete_member(const unsigned int& x) {
  delete_sub_node(x);
}

void NetNode::update_member(const unsigned int& x, const LnaNodePtr& _node) {
  update_sub_node(x, _node);
}

LnaNodePtr NetNode::get_member(const unsigned int& x) const {
  return get_sub_node(x);
}

size_t NetNode::num_members() const {
  return size();
}

/******************************************************************************
 * Implementation of the NetNode Class
 *****************************************************************************/

std::string StructuredNetNode::source_code() {
  std::stringstream result;
  result << name;

  if (!param_nodes.empty()) {
    result << "(";
    for (auto it = param_nodes.begin(); it != param_nodes.end(); ++it) {
      result << (*it)->source_code();
      if (it != param_nodes.end() - 1) {
        result << ", ";
      }
    }
    result << ")";
  }

  result << " {\n";
  result << "\n/**************************\n"
         << " *** Colour Definitions ***\n"
         << " **************************/\n";
  for (auto it = color_nodes.begin(); it != color_nodes.end(); ++it) {
    result << (*it)->source_code();
  }

  result << "\n/****************************\n"
         << " *** Function Definitions ***\n"
         << " ****************************/\n";
  for (auto it = function_nodes.begin(); it != function_nodes.end(); ++it) {
    result << (*it)->source_code();
  }

  result << "\n/*************************\n"
         << " *** Place Definitions ***\n"
         << " *************************/\n";
  for (auto it = place_nodes.begin(); it != place_nodes.end(); ++it) {
    result << (*it)->source_code();
  }

  result << "\n/******************************\n"
         << " *** Transition Definitions ***\n"
         << " ******************************/\n";
  for (auto it = transition_nodes.begin(); it != transition_nodes.end(); ++it) {
    result << (*it)->source_code();
  }

  result << "\n}";
  return result.str();
}

void StructuredNetNode::set_name(const std::string& _name) {
  name = _name;
}

std::string StructuredNetNode::get_name() const {
  return name;
}

void StructuredNetNode::add_parameter(const ParameterNodePtr& _node) {
  param_nodes.push_back(_node);
}

ParameterNodePtr StructuredNetNode::get_parameter(const unsigned int& x) {
  return param_nodes[x];
}

size_t StructuredNetNode::num_parameters() const {
  return param_nodes.size();
}

void StructuredNetNode::add_color(const LnaNodePtr& _color) {
  color_nodes.push_back(_color);
}

LnaNodePtr StructuredNetNode::get_color(const unsigned int& x) {
  return color_nodes[x];
}

size_t StructuredNetNode::num_colors() const {
  return color_nodes.size();
}

void StructuredNetNode::add_place(const LnaNodePtr& _place) {
  place_nodes.push_back(_place);
}

LnaNodePtr StructuredNetNode::get_place(const unsigned int& x) {
  return place_nodes[x];
}

size_t StructuredNetNode::num_places() const {
  return place_nodes.size();
}

void StructuredNetNode::add_function(const LnaNodePtr& _function) {
  function_nodes.push_back(_function);
}

LnaNodePtr StructuredNetNode::get_function(const unsigned int& x) {
  return function_nodes[x];
}

size_t StructuredNetNode::num_functions() const {
  return function_nodes.size();
}

void StructuredNetNode::add_transition(const LnaNodePtr& _transition) {
  transition_nodes.push_back(_transition);
}

LnaNodePtr StructuredNetNode::get_transition(const unsigned int& x) {
  return transition_nodes[x];
}

size_t StructuredNetNode::num_transitions() const {
  return transition_nodes.size();
}

/******************************************************************************
 * Implementation of the CommentNode Class
 *****************************************************************************/

std::string CommentNode::source_code() {
  return comment;
}

void CommentNode::set_comment(const std::string& _comment) {
  comment = _comment;
}

std::string CommentNode::get_comment() const {
  return comment;
}

/******************************************************************************
 * Implementation of the ColorNode Class
 *****************************************************************************/

std::string ColorNode::source_code() {
  std::string result = "type " + name + " : " + typeDef + ";\n";
  return result;
}

void ColorNode::set_name(const std::string& _name) {
  name = _name;
}

std::string ColorNode::get_name() const {
  return name;
}

void ColorNode::set_typeDef(const std::string& _typeDef) {
  typeDef = _typeDef;
}

std::string ColorNode::get_typeDef() const {
  return typeDef;
}

void ColorNode::set_init_value(const std::string& _value) {
  init_value = _value;
}

std::string ColorNode::get_init_value() const {
  return init_value;
}

/******************************************************************************
 * Implementation of the SubColorNode Class
 *****************************************************************************/

std::string SubColorNode::source_code() {
  std::string result =
      "subtype " + name + " : " + subColor->get_name() + " " + typeDef + ";\n";
  return result;
}

void SubColorNode::set_subColor(const ColorNodePtr _subcolor) {
  subColor = _subcolor;
}

ColorNodePtr SubColorNode::get_subColor() const {
  return subColor;
}

/******************************************************************************
 * Implementation of the Component Class
 *****************************************************************************/

std::string ComponentNode::source_code() {
  std::string result = type + " " + name + ";";
  return result;
}

void ComponentNode::set_name(const std::string& _name) {
  name = _name;
}

std::string ComponentNode::get_name() const {
  return name;
}

void ComponentNode::set_type(const std::string& _type) {
  type = _type;
}

std::string ComponentNode::get_type() const {
  return type;
}

/******************************************************************************
 * Implementation of the StructColorNode Class
 *****************************************************************************/

std::string StructColorNode::source_code() {
  std::string result = "type " + name + " : struct { ";

  for (auto it = components.begin(); it != components.end(); ++it) {
    result += (*it)->source_code();
  }

  result += "};\n";
  return result;
}

void StructColorNode::add_component(const ComponentNodePtr& _component) {
  components.push_back(_component);
}

ComponentNodePtr StructColorNode::get_component(const unsigned int& x) {
  return components[x];
}

ComponentNodePtr StructColorNode::get_component_by_name(
    const std::string& _name) {
  for (auto it = components.begin(); it != components.end(); ++it) {
    if ((*it)->get_name() == _name) {
      return (*it);
    }
  }
  return nullptr;
}

size_t StructColorNode::num_components() const {
  return components.size();
}

/******************************************************************************
 * Implementation of the ListColorNode Class
 *****************************************************************************/

std::string ListColorNode::source_code() {
  std::string result = "type " + name + " : list[" + index_type + "] of " +
                       element_type + " with capacity " + capacity + ";\n";
  return result;
}

void ListColorNode::set_index_type(const std::string& _index_type) {
  index_type = _index_type;
}

std::string ListColorNode::get_index_type() const {
  return index_type;
}

void ListColorNode::set_element_type(const std::string& _element_type) {
  element_type = _element_type;
}

std::string ListColorNode::get_element_type() const {
  return element_type;
}

void ListColorNode::set_capacity(const std::string& _capacity) {
  capacity = _capacity;
}

std::string ListColorNode::get_capacity() const {
  return capacity;
}

/******************************************************************************
 * Implementation of the ConstantNode Class
 *****************************************************************************/

std::string ConstantNode::source_code() {
  std::string result =
      "constant " + type + " " + name + ":=" + expression + ";\n";
  return result;
}

void ConstantNode::set_name(const std::string& _name) {
  name = _name;
}

std::string ConstantNode::get_name() const {
  return name;
}

void ConstantNode::set_type(const std::string& _type) {
  type = _type;
}

std::string ConstantNode::get_type() const {
  return type;
}

void ConstantNode::set_expression(const std::string& _expression) {
  expression = _expression;
}

std::string ConstantNode::get_expression() const {
  return expression;
}

/******************************************************************************
 * Implementation of the ParamNode Class
 *****************************************************************************/

std::string ParamNode::source_code() {
  std::string result = type + " " + name;
  return result;
}

void ParamNode::set_name(const std::string& _name) {
  name = _name;
}

std::string ParamNode::get_name() const {
  return name;
}

void ParamNode::set_type(const std::string& _type) {
  type = _type;
}

std::string ParamNode::get_type() const {
  return type;
}

/******************************************************************************
 * Implementation of the FunctionNode Class
 *****************************************************************************/

std::string FunctionNode::source_code() {
  std::string result = "function " + name + " (";
  for (auto it = parameters_spec.begin(); it != parameters_spec.end(); ++it) {
    result += (*it)->source_code();
    if (it != parameters_spec.end() - 1) {
      result += ", ";
    }
  }

  result += ")";
  if (!returnType.empty()) {
    result += " -> " + returnType;
  }

  result += (!body.empty()) ? "{\n" + body + "\n}\n" : ";\n";
  return result;
}

void FunctionNode::set_name(const std::string& _name) {
  name = _name;
}

std::string FunctionNode::get_name() const {
  return name;
}

void FunctionNode::add_parameter(const ParamNodePtr& _node) {
  parameters_spec.push_back(_node);
}

ParamNodePtr FunctionNode::get_parameter(const unsigned int& x) {
  return (x < parameters_spec.size()) ? parameters_spec[x] : nullptr;
}

void FunctionNode::set_returnType(const std::string& _returnType) {
  returnType = _returnType;
}

std::string FunctionNode::get_returnType() const {
  return returnType;
}

void FunctionNode::set_body(const std::string& _body) {
  body = _body;
}

std::string FunctionNode::get_body() const {
  return body;
}

/******************************************************************************
 * Implementation of the PlaceNode Class
 *****************************************************************************/

std::string PlaceNode::source_code() {
  std::string result = "place " + name + " {\n\tdom : " + domain + ";";

  if (!init.empty()) {
    result += "\n\tinit : " + init + ";";
  }

  if (!capacity.empty()) {
    result += "\n\tcapacity : " + capacity + ";";
  }

  if (!type.empty()) {
    result += "\n\ttype : " + type + ";";
  }

  result += "\n}\n";
  return result;
}

void PlaceNode::set_name(const std::string& _name) {
  name = _name;
}

std::string PlaceNode::get_name() const {
  return name;
}

void PlaceNode::set_domain(const std::string& _domain) {
  domain = _domain;
}

std::string PlaceNode::get_domain() const {
  return domain;
}

void PlaceNode::set_init(const std::string& _init) {
  init = _init;
}

std::string PlaceNode::get_init() const {
  return init;
}

void PlaceNode::set_capacity(const std::string& _capacity) {
  capacity = _capacity;
}

std::string PlaceNode::get_capacity() const {
  return capacity;
}

void PlaceNode::set_type(const std::string& _type) {
  type = _type;
}
std::string PlaceNode::get_type() const {
  return type;
}

std::string ArcNode::source_code() {
  std::string result = placeName + " : " + label + ";";
  return result;
}

/******************************************************************************
 * Implementation of the ArcNode Class
 *****************************************************************************/
void ArcNode::set_placeName(const std::string& _placeName) {
  placeName = _placeName;
}

std::string ArcNode::get_placeName() const {
  return placeName;
}

void ArcNode::set_label(const std::string& _label) {
  label = _label;
}

std::string ArcNode::get_label() const {
  return label;
}

/******************************************************************************
 * Implementation of the TransitionNode Class
 *****************************************************************************/

std::string TransitionNode::source_code() {
  std::string result = "transition " + name + " {\n\tin {\n";

  // ingoing arcs
  for (auto it = inArcs.begin(); it != inArcs.end(); ++it) {
    result += "\t\t" + (*it)->source_code() + "\n";
  }

  // outgoing arcs
  result += "\t}\n\tout {\n";
  for (auto it = outArcs.begin(); it != outArcs.end(); ++it) {
    result += "\t\t" + (*it)->source_code() + "\n";
  }
  result += "\t}\n";

  // bound variables
  if (!lets.empty()) {
    result += "\tlet {\n";
    for (auto it = lets.begin(); it != lets.end(); ++it) {
      result += "\t\t" + (*it) + "\n";
    }
    result += "\t\t}\n";
  }

  // inhibitor arcs
  if (!inhibitArcs.empty()) {
    result += "\tinhibit {\n";
    for (auto it = inhibitArcs.begin(); it != inhibitArcs.end(); ++it) {
      result += "\t\t" + (*it)->source_code() + "\n";
    }
    result += "\t}\n";
  }

  if (!guard.empty()) {
    result += "\tguard : " + guard + "\n";
  }

  if (!priority.empty()) {
    result += "\tpriority : " + priority + "\n";
  }

  if (!description.empty()) {
    result += "\tdescription : " + description + "\n";
  }

  if (!safe.empty()) {
    result += "\tsafe\n";
  }

  result += "}\n";
  return result;
}

void TransitionNode::set_name(const std::string& _name) {
  name = _name;
}

std::string TransitionNode::get_name() const {
  return name;
}

void TransitionNode::add_inArc(const ArcNodePtr& _node) {
  inArcs.push_back(_node);
}

ArcNodePtr TransitionNode::get_in_arc_by_name(const std::string& _name) {
  for (auto it = inArcs.begin(); it != inArcs.end(); ++it) {
    if ((*it)->get_placeName() == _name) {
      return *it;
    }
  }
  return nullptr;
}

void TransitionNode::add_outArc(const ArcNodePtr& _node) {
  outArcs.push_back(_node);
}

ArcNodePtr TransitionNode::get_out_arc_by_name(const std::string& _name) {
  for (auto it = outArcs.begin(); it != outArcs.end(); ++it) {
    if ((*it)->get_placeName() == _name) {
      return *it;
    }
  }
  return nullptr;
}

void TransitionNode::add_inhibitArc(const ArcNodePtr& _node) {
  inhibitArcs.push_back(_node);
}

void TransitionNode::set_guard(const std::string& _guard) {
  guard = _guard;
}

std::string TransitionNode::get_guard() const {
  return guard;
}

void TransitionNode::set_priority(const std::string& _priority) {
  priority = _priority;
}

std::string TransitionNode::get_priority() const {
  return priority;
}

void TransitionNode::set_description(const std::string& _description) {
  description = _description;
}

std::string TransitionNode::get_description() const {
  return description;
}

void TransitionNode::set_safe(const std::string& _safe) {
  safe = _safe;
}
std::string TransitionNode::get_safe() const {
  return safe;
}

void TransitionNode::add_let(const std::string& _node) {
  lets.push_back(_node);
}

}  // namespace HELENA