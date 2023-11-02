#include "Helena.hpp"

namespace HELENA{

/**
 * The getter to get the node type
*/
LnaNodeType LnaNode::get_node_type() const {
    return node_type;
}

/** Add subnode to the collection
 */ 
void LnaNode::append_sub_node(const LnaNodePtr& _node) {
    lna_nodes.push_back(_node);
}

/** Delete the sub node
 */ 
void LnaNode::delete_sub_node(const unsigned int& x) {
    lna_nodes.erase(lna_nodes.begin() + x);
}
/** Update the sub node
 */ 
void LnaNode::update_sub_node(const unsigned int& x, const LnaNodePtr _node) {
    lna_nodes[x] = _node;
}
/** Get the sub node
 */
LnaNodePtr LnaNode::get_sub_node(const unsigned int& x) const {
    return lna_nodes[x];
}

/** Get the size of the node
 */
size_t LnaNode::size() {
    return lna_nodes.size();
}

/** Design the interface for the output lna file for Net
 */
std::string NetNode::source_code() {
    std::stringstream result;
    result << name;
    if (param_nodes.size() != 0) {
        result << "(";
        for (auto it = param_nodes.begin(); it != param_nodes.end(); ++it) {
            result << (*it)->source_code();
            if (it != param_nodes.end()-1)
                result << ", ";
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

/** Set name for the node
 */ 
void NetNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the node
 */
std::string NetNode::get_name() const {
    return name;
}

/** Add parametters to the collection
 */
void NetNode::add_parameter(const ParameterNodePtr& _node) {
    param_nodes.push_back(_node);
}
/** Add member to the node
 */
void NetNode::add_member(const LnaNodePtr& _node) {
    append_sub_node(_node);
}

/** Delete the member of the node
 */
void NetNode::delete_member(const unsigned int& x) {
    delete_sub_node(x);
}
/** Update the member of the node
 */
void NetNode::update_member(const unsigned int& x, const LnaNodePtr& _node) {
    update_sub_node(x, _node);
}
/** Get a member of the node
 */
LnaNodePtr NetNode::get_member(const unsigned int& x) {
    return get_sub_node(x);
}
/** Get the size of the net
 */
size_t NetNode::num_members() {
    return size();
}


/** Design the interface for the output lna file of Structured Net
 */
std::string StructuredNetNode::source_code() {
    std::stringstream result;
    result << name;
    if (param_nodes.size() != 0) {
        result << "(";
        for (auto it = param_nodes.begin(); it != param_nodes.end(); ++it) {
            result << (*it)->source_code();
            if (it != param_nodes.end()-1)
                result << ", ";
        }
        result << ")";        
    }
    result << " {\n";
    result << "\n/**************************\n"
           <<   " *** Colour Definitions ***\n"
           <<   " **************************/\n";
    for (auto it = color_nodes.begin(); it != color_nodes.end(); ++it) {
        result << (*it)->source_code();
    }
    result << "\n/****************************\n"
           <<   " *** Function Definitions ***\n"
           <<   " ****************************/\n";
    for (auto it = function_nodes.begin(); it != function_nodes.end(); ++it) {
        result << (*it)->source_code();
    }
    result << "\n/*************************\n"
           <<   " *** Place Definitions ***\n"
           <<   " *************************/\n";
    for (auto it = place_nodes.begin(); it != place_nodes.end(); ++it) {
        result << (*it)->source_code();
    }
    result << "\n/******************************\n"
           <<   " *** Transition Definitions ***\n"
           <<   " ******************************/\n";
    for (auto it = transition_nodes.begin(); it != transition_nodes.end(); ++it) {
        result << (*it)->source_code();
    }
    result << "\n}";
    return result.str();
}

/** Set name for the node
 */ 
void StructuredNetNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the node
 */
std::string StructuredNetNode::get_name() const {
    return name;
}
/** Add parametters to the collection
 */
void StructuredNetNode::add_parameter(const ParameterNodePtr& _node) {
    param_nodes.push_back(_node);
}
/** Get a parameter of the net
 */
ParameterNodePtr StructuredNetNode::get_parameter(const unsigned int& x){
    return param_nodes[x];
}
/** Get the number of parameter in net
 */
size_t StructuredNetNode::num_parameters(){
    return param_nodes.size();
}
/** Add color to the net
 */
void StructuredNetNode::add_color(const LnaNodePtr& _color) {
    color_nodes.push_back(_color);
}
/** Get a color of the net
 */
LnaNodePtr StructuredNetNode::get_color(const unsigned int& x) {
    return color_nodes[x];
}
/** Get the number of color in net
 */
size_t StructuredNetNode::num_colors() {
    return color_nodes.size();
}

/** Add place to the net
 */
void StructuredNetNode::add_place(const LnaNodePtr& _place) {
    place_nodes.push_back(_place);
}
/** Get a place of the net
 */
LnaNodePtr StructuredNetNode::get_place(const unsigned int& x) {
    return place_nodes[x];
}
/** Get the number of place in net
 */
size_t StructuredNetNode::num_places() {
    return place_nodes.size();
}

/** Add function to the net
 */
void StructuredNetNode::add_function(const LnaNodePtr& _function) {
    function_nodes.push_back(_function);
}
/** Get a function of the net
 */
LnaNodePtr StructuredNetNode::get_function(const unsigned int& x) {
    return function_nodes[x];
}
/** Get the number of function in net
 */
size_t StructuredNetNode::num_functions() {
    return function_nodes.size();
}

/** Add transition to the net
 */
void StructuredNetNode::add_transition(const LnaNodePtr& _transition) {
    transition_nodes.push_back(_transition);
}
/** Get a transition of the net
 */
LnaNodePtr StructuredNetNode::get_transition(const unsigned int& x) {
    return transition_nodes[x];
}
/** Get the number of transition in net
 */
size_t StructuredNetNode::num_transitions() {
    return transition_nodes.size();
}

/** Connect the name and number 
 */
std::string ParameterNode::source_code() {
    std::string result = name + " := " + number;
    return result;
}
/** Set name to the parameter node
 */
void ParameterNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the parameter node
 */
std::string ParameterNode::get_name() const {
    return name;
}
/** Set number for the parameter node
 */
void ParameterNode::set_number(const std::string& _number) {
    number = _number;
}
/** Get number of the parameter node
 */
std::string ParameterNode::get_number() const {
    return number;
}

/** Return comment
 */
std::string CommentNode::source_code(){
    return comment;
}
/** Set comment for the comment node
 */
void CommentNode::set_comment(const std::string& _comment){
    comment = _comment;
}
/** Get comment of the comment node
 */
std::string CommentNode::get_comment(){
    return comment;
}


/** Append information
 */
std::string ColorNode::source_code() {
    //visit(this);
    std::string result = "type " + name + " : " + typeDef + ";\n";
    return result;
}
/** Set name for the colour node
 */
void ColorNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the colour node
 */
std::string ColorNode::get_name() const {
    return name;
}
/** Set type definition
 */
void ColorNode::set_typeDef(const std::string& _typeDef) {
    typeDef = _typeDef;
}
/** Get type definition
 */
std::string ColorNode::get_typeDef() const {
    return typeDef;
}
/** Set init value
 */
void ColorNode::set_init_value(const std::string& _value) {
    init_value = _value;
}
/** Get type definition
 */
std::string ColorNode::get_init_value() const {
    return init_value;
}
/** Connect the information for the Component node
 */
std::string ComponentNode::source_code() {
    std::string result = type + " " + name + ";";
    return result;
}
/** Set name for the component node
 */
void ComponentNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the component node
 */
std::string ComponentNode::get_name() const {
    return name;
}
/** Set type of the component node
 */
void ComponentNode::set_type(const std::string& _type) {
    type = _type;
}
/** Get type of the component node
 */
std::string ComponentNode::get_type() const {
    return type;
}
/** Process the Sub colour node
 */
std::string SubColorNode::source_code() {
    std::string result = "subtype " + name + " : " + supColor->get_name() + " " + typeDef + ";\n";
    return result;
}
/** Set sub color node
 */
void SubColorNode::set_supColor(const ColorNodePtr _supColor) {
    supColor = _supColor;
}
/** Get sub colo node
 */
ColorNodePtr SubColorNode::get_supColor() const {
    return supColor;
}
/** Process for the struct color node
 */
std::string StructColorNode::source_code() {
    std::string result = "type " + name + " : struct { ";
    for (auto it = components.begin(); it != components.end(); ++it)
        result += (*it)->source_code();
    result += "};\n";
    return result;
}
/** Add component to the struct
 */
void StructColorNode::add_component(const ComponentNodePtr& _component) {
    components.push_back(_component);
}
/** Get component of the struct color node
 */
ComponentNodePtr StructColorNode::get_component(const unsigned int& x) {
    return components[x];
}
/** Get component by name
 */
ComponentNodePtr StructColorNode::get_component_by_name(const string& _name) {
    for (auto it = components.begin(); it != components.end(); ++it)
            if ((*it)->get_name() == _name)
                return (*it);
    return nullptr;
}
/** Get size of the components
 */
size_t StructColorNode::num_components() {
    return components.size();
}
/** Processing the List of colour node
 */
std::string ListColorNode::source_code() {
    //visit(this);
    std::string result = "type " + name + " : list[" + index_type + "] of " + element_type + " with capacity " + capacity +";\n";
    return result;
}
/** Set value for index type
 */
void ListColorNode::set_index_type(const std::string& _index_type) {
    index_type = _index_type;
}
/** Get value of the index type
 */
std::string ListColorNode::get_index_type() const {
    return index_type;
}
/** Set value for the element type
 */
void ListColorNode::set_element_type(const std::string& _element_type) {
    element_type = _element_type;
}
/** Get value of the element type
 */
std::string ListColorNode::get_element_type() const {
    return element_type;
}
/** Set value for the capacity
 */
void ListColorNode::set_capacity(const std::string& _capacity) {
    capacity = _capacity;
}
/** Get value of the capacity
 */ 
std::string ListColorNode::get_capacity() const {
    return capacity;
}
/** Processing for the constant node
 */
std::string ConstantNode::source_code() {
    //visit(this);
    std::string result = "constant " + type + " " + name + ":=" + expression + ";\n";
    return result;
}
/** Set name for the constant node
 */
void ConstantNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name ò the constant node
 */
std::string ConstantNode::get_name() const {
    return name;
}
/** Set type for the constant node
 */
void ConstantNode::set_type(const std::string& _type) {
    type = _type;
}
/** Get type of the constant node
 */
std::string ConstantNode::get_type() const {
    return type;
}
/** Set expression for the constant node
 */
void ConstantNode::set_expression(const std::string& _expression) {
    expression = _expression;
}
/** Get expression of the constant node
 */
std::string ConstantNode::get_expression() const {
    return expression;
}
/** Processing for the Parameter node
 */
std::string ParamNode::source_code() {
    std::string result = type + " " + name;
    return result;
}
/** Set name for the Parameter node
 */
void ParamNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the parameter node
 */
std::string ParamNode::get_name() const {
    return name;
}
/** Set type for the parameter node
 */
void ParamNode::set_type(const std::string& _type) {
    type = _type;
}
/** Get type of the parameter node
 */
std::string ParamNode::get_type() const {
    return type;
}
/** Processing for the function node
 */
std::string FunctionNode::source_code() {
    std::string result = "function " + name + " (";
    for (auto it = parameters_spec.begin(); it != parameters_spec.end(); ++it) {
            result += (*it)->source_code();
            if (it != parameters_spec.end()-1)
                result += ", ";
    }
    result += ")";
    if (returnType != "")
        result += " -> " + returnType;
    if (body != "")
        result += "{\n" + body + "\n}\n";
    else 
        result += ";\n";
    return result;
}
/** Set name of the Function node
 */
void FunctionNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the Function node
 */
std::string FunctionNode::get_name() const {
    return name;
}
/** Get parameter of the function node
 */
ParamNodePtr FunctionNode::get_parameter(const unsigned int& x){
    if(x < parameters_spec.size())
        return parameters_spec[x];
}
/** Set return type of the Function node
 */
void FunctionNode::set_returnType(const std::string& _returnType) {
    returnType = _returnType;
}
/** Get the return type
 */
std::string FunctionNode::get_returnType() const {
    return returnType;
}
/** Add the parameter of the fucntion
 */
void FunctionNode::add_parameter(const ParamNodePtr& _node) {
    parameters_spec.push_back(_node);
}
/** Set body for the function
 */
void FunctionNode::set_body(const std::string& _body) {
    body = _body;
}
/** Get the body of the fucntion
 */
std::string FunctionNode::get_body() const {
    return body;
}
/** Processing the Place node
 */
std::string PlaceNode::source_code() {
    std::string result = "place " + name + " {\n\tdom : " + domain + ";";
    if (init != "")
        result += "\n\tinit : " + init + ";";
    if (capacity != "")
    if (capacity != "")
        result += "\n\tcapacity : " + capacity + ";";
    if (type != "")
        result += "\n\ttype : " + type + ";";
    result += "\n}\n";
    return result;
}
/** Set name of the place node
 */
void PlaceNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the place node
 */
std::string PlaceNode::get_name() const {
    return name;
}
/** Set domain of the place node
 */
void PlaceNode::set_domain(const std::string& _domain) {
    domain = _domain;
}
/** Get domain of the place node
 */
std::string PlaceNode::get_domain() const {
    return domain;
}
/** Set initilize for the place node
 */
void PlaceNode::set_init(const std::string& _init) {
    init = _init;
}
/** Get initialize of the place node
 */
std::string PlaceNode::get_init() const {
    return init;
}
/** Set the capacity of the place node
 */
void PlaceNode::set_capacity(const std::string& _capacity) {
    capacity = _capacity;
}
/** Get capacity of the place node
 */
std::string PlaceNode::get_capacity() const {
    return capacity;
}
/** Set type of the place node
 */
void PlaceNode::set_type(const std::string& _type) {
    type = _type;
}
/** Get type of the place node
 */
std::string PlaceNode::get_type() const {
    return type;
}
/** Processing for the Arc node
 */
std::string ArcNode::source_code() {
    std::string result = placeName + " : " + label + ";";
    return result;
}
/** Set place name
 */
void ArcNode::set_placeName(const std::string& _placeName) {
    placeName = _placeName;
}
/** Get place name
 */
std::string ArcNode::get_placeName() const {
    return placeName;
}
/** Set label for the Arc node
 */
void ArcNode::set_label(const std::string& _label) {
    label = _label;
}
/** Get label for the Arc node
 */
std::string ArcNode::get_label() const {
    return label;
}
/** Processing for the Transition node
 */
std::string TransitionNode::source_code() {
    std::string result = "transition " + name + " {\n\tin {\n";
    for (auto it = inArcs.begin(); it != inArcs.end(); ++it)
        result += "\t\t" + (*it)->source_code() + "\n";
    result += "\t}\n\tout {\n";
    for (auto it = outArcs.begin(); it != outArcs.end(); ++it)
        result += "\t\t" + (*it)->source_code() + "\n";
    result += "\t}\n";
    if (lets.size() != 0) {
        result += "\tlet {\n";
        for(auto it = lets.begin(); it != lets.end(); ++it){
            result += "\t\t" + (*it) + "\n";
        }
        result += "\t\t}\n";
    }
    if (inhibitArcs.size() != 0) {
        result += "\tinhibit {\n";
        for (auto it = inhibitArcs.begin(); it != inhibitArcs.end(); ++it)
            result += "\t\t" + (*it)->source_code() + "\n";
        result += "\t}\n";
    }
    if (guard != "")
        result += "\tguard : " + guard + "\n";
    if (priority != "")
        result += "\tpriority : " + priority + "\n";
    if (description != "")
        result += "\tdescription : " + description + "\n";
    if (safe != "")
        result += "\tsafe\n";
    result += "}\n";
    return result;
}

/** Set name for the transition node
 */  
void TransitionNode::set_name(const std::string& _name) {
    name = _name;
}
/** Get name of the Transition node
 */
std::string TransitionNode::get_name() const {
    return name;
}
/** Add an input Arc node to the net
 */
void TransitionNode::add_inArc(const ArcNodePtr& _node) {
    inArcs.push_back(_node);
}
/** Add an output Arc node to the net
 */
void TransitionNode::add_outArc(const ArcNodePtr& _node) {
    outArcs.push_back(_node);
}
/** Get in arc by input name
 */
ArcNodePtr TransitionNode::get_in_arc_by_name(const std::string& _name){
    for(auto it = inArcs.begin(); it != inArcs.end(); ++it){
        if((*it)->get_placeName() == _name){
            return *it;
        }
    }
    return nullptr;
}
/** Get out arc by input name
 */
ArcNodePtr TransitionNode::get_out_arc_by_name(const std::string& _name){
    for(auto it = outArcs.begin(); it != outArcs.end(); ++it){
        if((*it)->get_placeName() == _name){
            return *it;
        }
    }
    return nullptr;
}

/** Add an inhibit Arc to the net
 */
void TransitionNode::add_inhibitArc(const ArcNodePtr& _node) {
    inhibitArcs.push_back(_node);
}
/** Set guard for the transition
 */
void TransitionNode::set_guard(const std::string& _guard) {
    guard = _guard;
}
/** Get the guard of the transition
 */
std::string TransitionNode::get_guard() const {
    return guard;
}
/** Set priority for the transition
 */
void TransitionNode::set_priority(const std::string& _priority) {
    priority = _priority;
}
/** Get priority of the Transition
 */
std::string TransitionNode::get_priority() const {
    return priority;
}
/** Set description for the transitions
 */
void TransitionNode::set_description(const std::string& _description) {
    description = _description;
}
/** Get the description for the transition
 */
std::string TransitionNode::get_description() const {
    return description;
}
/** Set safe for the Transition node
 */
void TransitionNode::set_safe(const std::string& _safe) {
    safe = _safe;
}
/** Get safe of the transition node
 */
std::string TransitionNode::get_safe() const {
    return safe;
}
/** Add a _node to let
 */
void TransitionNode::add_let(const std::string& _node){
    lets.push_back(_node);
}

}