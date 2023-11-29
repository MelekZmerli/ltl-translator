#include "unfolder.hpp"

#include <stddef.h>

#include <algorithm>
#include <iostream>
#include <list>
#include <memory>
#include <random>

#include "LNAAnalyser.hpp"
#include "utils.hpp"

Unfolder::Unfolder(const HELENA::StructuredNetNodePtr& _context,
                   const std::string& _context_type,
                   std::stringstream& _sol_lna_stream,
                   const nlohmann::json& lna_json,
                   const nlohmann::json& ltl_json,
                   const nlohmann::json& im_json)
    : sol_information(lna_json),
      ltl_information(ltl_json),
      im_information(im_json),
      cpn_context(_context),
      context_type(_context_type) {
  unfolded_func = FindUnfoldedFunctions();
  cpn_model = analyseLnaFile(_sol_lna_stream);
}

std::vector<std::string> Unfolder::FindUnfoldedFunctions() {
  std::vector<std::string> unfolded_func;
  unfolded_func.push_back("state");

  // Get the variables involved in the property
  std::vector<std::string> list_required_variables;
  std::string ltl_type = ltl_information.at("type");
  auto ltl_param = ltl_information.at("params");
  if (ltl_type == "general") {
    std::string ltl_name = ltl_param.at("name");
    if (ltl_name == "under_over_flow") {
      auto inputs = ltl_param.at("inputs");
      std::string variable = inputs.at("selected_variable");
      list_required_variables.push_back(variable);
    }
  } else if (ltl_type == "specific") {
    std::vector<std::string> temp =
        LTL2PROP::LTLTranslator::getListVariableFromFormula(
            ltl_param.at("formula"));
    for (const auto& op : temp) {
      std::vector<std::string> temp_split = split_ex(op, ".", 2);
      std::string opr_type = (temp_split.size() == 2) ? temp_split[1] : "var";
      std::string opr_name = substr_by_edge(op, "'", "'");

      if (opr_type == "func") {
        unfolded_func.push_back(opr_name);
      } else if (opr_type == "var") {
        list_required_variables.push_back(opr_name);
      }
    }
  }

  // Get the global variables in the smart contract
  std::map<std::string, std::string> global_variables;
  for (const auto& gv : sol_information.at("globalVariables")) {
    std::string gv_name = gv.at("name");
    global_variables[gv_name] = gv.at("placeType");
  }

  // Get the functions with the local variables involved in the LTL property
  auto functions = sol_information.at("functions");
  for (const auto& function : functions) {
    // Get local variables in the smart contract
    std::map<std::string, std::string> local_var;
    for (const auto& lv : function.at("localVariables")) {
      std::string lv_name = lv.at("name");
      local_var[lv_name] = lv.at("place");
    }

    // Get the function of the local variables involved in the LTL property
    for (const auto var : list_required_variables) {
      if (local_var.find(var) != local_var.end()) {
        unfolded_func.push_back(function.at("name"));
        break;
      }
    }
  }

  // Add all the functions if a global variable is involved in the property
  for (const auto var : list_required_variables) {
    if (global_variables.find(var) != global_variables.end()) {
      for (const auto& function : functions) {
        unfolded_func.push_back(function.at("name"));
      }
      break;
    }
  }

  return unfolded_func;
}

HELENA::StructuredNetNodePtr Unfolder::analyseLnaFile(
    std::stringstream& _sol_lna_stream) {
  HELENA::StructuredNetNodePtr model =
      std::make_shared<HELENA::StructuredNetNode>();
  std::list<std::string> _sol_lines;

  // read the CPN model of the smart contract (.lna file)
  std::string new_line;
  while (std::getline(_sol_lna_stream, new_line)) {
    if (!new_line.empty()) {
      std::string temp = std::string(new_line);
      trim_ex(temp);
      if (!temp.empty()) {
        _sol_lines.emplace_back(new_line);
      }
    }
  }

  std::list<std::string>::iterator ptr_pointer_line = _sol_lines.begin();
  std::list<std::string>::iterator ptr_pointer_end = _sol_lines.end();

  // Get name and parameters of the CPN model
  while (ptr_pointer_line != ptr_pointer_end) {
    std::string model_name = get_first_alpha_only_string(*ptr_pointer_line);
    if (!model_name.empty()) {
      model->set_name(model_name);

      // parse parameters of the CPN model
      std::string parameter_def = substr_by_edge(*ptr_pointer_line, "(", ")");
      std::vector<std::string> parameters = split(parameter_def, ",");
      for (const auto& parameter : parameters) {
        std::vector<std::string> param = split_ex(parameter, ":=", 2);
        if (param.size() == 2) {
          trim_ex(param[0]);
          trim_ex(param[1]);

          HELENA::ParameterNodePtr mpr =
              std::make_shared<HELENA::ParameterNode>();
          mpr->set_name(param[0]);
          mpr->set_number(param[1]);
          model->add_parameter(mpr);
        }
      }
      break;
    }
    ptr_pointer_line++;
  }

  bool wait2set = false;
  std::string current_submodel_name;
  while (ptr_pointer_line != ptr_pointer_end) {
    // Get name of a submodel (i.e., function)
    if (retrieve_string_element(*ptr_pointer_line, 1, " ") == "Function:") {
      current_submodel_name =
          retrieve_string_element(*ptr_pointer_line, 2, " ");
      wait2set = true;
    } else {
      // Get content of a submodel
      std::string keyword = get_first_alpha_only_string(*ptr_pointer_line);
      if (keyword == HELENA::TRANSITION_TOKEN) {
        HELENA::TransitionNodePtr transition =
            HELENA::handleTransition(ptr_pointer_line, ptr_pointer_end);
        if (wait2set) {
          model->add_transition(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
          wait2set = false;
        }
        model->add_transition(transition);
      } else if (keyword == HELENA::PLACE_TOKEN) {
        HELENA::PlaceNodePtr place =
            HELENA::handlePlace(ptr_pointer_line, ptr_pointer_end);
        if (wait2set) {
          model->add_place(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
          wait2set = false;
        }
        model->add_place(place);
      } else if (keyword == HELENA::TYPE_TOKEN ||
                 keyword == HELENA::SUBTYPE_TOKEN) {
        HELENA::ColorNodePtr color =
            HELENA::handleColor(ptr_pointer_line, ptr_pointer_end);
        model->add_color(color);
      } else if (keyword == HELENA::FUNCTION_TOKEN) {
        HELENA::FunctionNodePtr function =
            HELENA::handleFunction(ptr_pointer_line, ptr_pointer_end);
        model->add_function(function);
      }
    }

    ptr_pointer_line++;
  }

  return model;
}

void Unfolder::initialMarkingSetting() {
  // create array color
  HELENA::ListColorNodePtr uint_array =
      std::make_shared<HELENA::ListColorNode>();
  uint_array->set_name("UINT_ARRAY");
  uint_array->set_index_type("UINT");
  uint_array->set_element_type("UINT");
  uint_array->set_capacity("1000");
  cpn_model->add_color(std::static_pointer_cast<HELENA::ColorNode>(uint_array));

  // get number of users from the initial marking file
  std::string s_numberOfUser = im_information.at("NumberOfUser");
  int numberOfUser = std::stoi(s_numberOfUser);

  // create parameter node with the number of users
  HELENA::ParameterNodePtr users = std::make_shared<HELENA::ParameterNode>();
  users->set_name("users");
  users->set_number(s_numberOfUser);
  cpn_model->add_parameter(users);

  // parse balance parameter of the initial marking
  std::string balance_value;
  auto balance = im_information.at("balance");
  std::string balance_type = balance.at("type");
  if (balance_type == "fixed") {
    std::string fixed_value = balance.at("fixed");
    balance_value = repeat_word(fixed_value, numberOfUser);
  } else if (balance_type == "map") {
    std::string map_value = balance.at("map");
    balance_value = map_value;
  } else if (balance_type == "random") {
    auto random_value = balance.at("random");
    std::string s_from = random_value.at("from");
    std::string s_to = random_value.at("to");

    std::random_device rd;   // obtain a random number from hardware
    std::mt19937 gen(rd());  // seed the generator
    std::uniform_int_distribution<> distr(std::stoi(s_from), std::stoi(s_to));

    balance_value = std::to_string(distr(gen));
    for (int i = 1; i < numberOfUser; i++) {
      balance_value += "," + std::to_string(distr(gen));
    }
  }

  // create constant node with the user balance value
  HELENA::ConstantNodePtr user_balance =
      std::make_shared<HELENA::ConstantNode>();
  user_balance->set_name("user_balance");
  user_balance->set_type("UINT_ARRAY");
  user_balance->set_expression("|" + balance_value + "|");
  cpn_model->add_color(user_balance);

  // parse the functions and their arguments in the initial marking
  for (const auto& sc : im_information.at("smart_contract")) {
    std::string sc_name = sc.at("name");
    if (sc_name == cpn_model->get_name()) {
      for (const auto& function : sc.at("functions")) {
        std::string function_name = function.at("name");
        auto f_sender_value = function.at("sender_value");
        std::string sf_from = f_sender_value.at("from");
        std::string sf_to = f_sender_value.at("to");

        int f_from = std::stoi(sf_from);
        int f_to = std::stoi(sf_to);

        std::string fs_sender_value = generate_seq(f_from, f_to);

        HELENA::ParameterNodePtr function_sender_range =
            std::make_shared<HELENA::ParameterNode>();
        function_sender_range->set_name(function_name + "_sdr");
        function_sender_range->set_number(std::to_string(f_to - f_from + 1));
        cpn_model->add_parameter(function_sender_range);

        HELENA::ConstantNodePtr function_sender_value =
            std::make_shared<HELENA::ConstantNode>();
        function_sender_value->set_name(function_name + "_sender_value");
        function_sender_value->set_type("UINT_ARRAY");
        function_sender_value->set_expression("|" + fs_sender_value + "|");
        cpn_model->add_color(function_sender_value);
      }
    }
  }

  // create map with unfolded functions
  std::map<std::string, std::string> P_functions;
  for (const auto& f : unfolded_func) {
    P_functions["P_" + f] = f;
  }

  // initialize places related to the unfolded functions
  for (size_t i = 0; i < cpn_model->num_places(); i++) {
    HELENA::LnaNodePtr node = cpn_model->get_place(i);
    if (node->get_node_type() == HELENA::LnaNodeTypePlace) {
      HELENA::PlaceNodePtr place =
          std::static_pointer_cast<HELENA::PlaceNode>(node);
      std::string place_name = place->get_name();
      if (P_functions.find(place_name) != P_functions.end()) {
        std::string func_name = P_functions[place_name];
        std::string init_place;

        init_place +=
            "for (i in ADDRESS range 1 .. ADDRESS (users), j in UINT range 0 "
            ".. UINT(" +
            func_name + "_sdr-1" + "))";
        init_place += " <( {{i, UINT(user_balance[UINT(i-1)])}," + func_name +
                      "_sender_value[j]" + "})>";
        place->set_init(init_place);
      }
    }
  }
}

std::map<std::string, std::string> Unfolder::unfoldModel() {
  // apply initial marking
  initialMarkingSetting();

  // unfold the behavioral context
  HELENA::StructuredNetNodePtr unfold_model;
  if (context_type == "DCR" || context_type == "CPN") {
    unfold_model = unfoldModelWithCPNContext();
  } else if (context_type == "FREE") {
    unfold_model = unfoldModelWithFreeContext();
  } else {
    unfold_model = std::make_shared<HELENA::StructuredNetNode>();
  }

  // parse the LTL formula taking into account the CPN model
  LTL2PROP::LTLTranslator ltl_translator =
      LTL2PROP::LTLTranslator(sol_information, ltl_information);
  std::map<std::string, std::string> ltl_result = ltl_translator.translate();

  // add the propositions to the final CPN model
  unfold_model->add_transition(
      std::make_shared<HELENA::CommentNode>(ltl_result["propositions"]));

  // return the final CPN model and the LTL property to verify
  std::map<std::string, std::string> result;
  result["lna"] = unfold_model->source_code();
  result["prop"] = ltl_result["property"];

  return result;
}

std::string Unfolder::get_model_name_from_comment(
    const HELENA::CommentNodePtr& _comment) {
  std::string name = substr_by_edge(_comment->get_comment(), "Function:", "*/");
  trim_ex(name);
  return name;
}

HELENA::StructuredNetNodePtr Unfolder::unfoldModelWithCPNContext() {
  HELENA::StructuredNetNodePtr unfold_model =
      std::make_shared<HELENA::StructuredNetNode>();

  unfold_model->set_name(cpn_model->get_name());

  if (!unfolded_func.empty()) {
    std::string current_submodel_name;

    /**************************************************************************
     * Handling context CPN model
     **************************************************************************/

    // add parameters from context model to the unfolded model
    for (size_t i = 0; i < cpn_context->num_parameters(); i++) {
      unfold_model->add_parameter(cpn_context->get_parameter(i));
    }

    // add colors from context model to the unfolded model
    for (size_t i = 0; i < cpn_context->num_colors(); i++) {
      unfold_model->add_color(cpn_context->get_color(i));
    }

    // add functions from context to the unfolded model
    for (size_t i = 0; i < cpn_context->num_functions(); i++) {
      unfold_model->add_function(cpn_context->get_function(i));
    }

    // add places from context involded in the formula to the unfolded model
    for (size_t i = 0; i < cpn_context->num_places(); i++) {
      HELENA::LnaNodePtr node = cpn_context->get_place(i);

      if (node->get_node_type() == HELENA::LnaNodeTypeComment) {
        // get name of the submodel
        current_submodel_name = get_model_name_from_comment(
            std::static_pointer_cast<HELENA::CommentNode>(node));

        // check if the submodel need to be unfolded
        // i.e., it's involved in the property
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_place(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
        }
      } else if (node->get_node_type() == HELENA::LnaNodeTypePlace) {
        // check if the  place need to be unfolded
        // i.e., it's involved in the property
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_place(
              std::static_pointer_cast<HELENA::PlaceNode>(node));
        }
      }
    }

    // add transitions from context involded in the formula to the unfolded
    // model
    for (size_t i = 0; i < cpn_context->num_transitions(); i++) {
      HELENA::LnaNodePtr node = cpn_context->get_transition(i);

      if (node->get_node_type() == HELENA::LnaNodeTypeComment) {
        // add transition to the unfolded model
        current_submodel_name = get_model_name_from_comment(
            std::static_pointer_cast<HELENA::CommentNode>(node));
        unfold_model->add_transition(std::make_shared<HELENA::CommentNode>(
            "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
      } else if (node->get_node_type() == HELENA::LnaNodeTypeTransition) {
        HELENA::TransitionNodePtr transition =
            std::static_pointer_cast<HELENA::TransitionNode>(node);
        // check if the transition is involded in the formula
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          // add incoming arc to the transition
          HELENA::ArcNodePtr cflow_arc_in = std::make_shared<HELENA::ArcNode>();
          cflow_arc_in->set_placeName("state_cflow");
          cflow_arc_in->set_label("epsilon");
          transition->add_inArc(cflow_arc_in);

          // add outgoing arc to the transition
          HELENA::ArcNodePtr cflow_arc_out =
              std::make_shared<HELENA::ArcNode>();
          cflow_arc_out->set_placeName(current_submodel_name + "_cflow");
          cflow_arc_out->set_label("epsilon");
          transition->add_outArc(cflow_arc_out);

          // add transition to the unfolded model
          unfold_model->add_transition(transition);
        } else {
          // add incoming arc to the transition
          HELENA::ArcNodePtr cflow_arc_in = std::make_shared<HELENA::ArcNode>();
          cflow_arc_in->set_placeName("state_cflow");
          cflow_arc_in->set_label("epsilon");
          transition->add_inArc(cflow_arc_in);

          // add outgoing arc to the transition
          HELENA::ArcNodePtr cflow_arc_out =
              std::make_shared<HELENA::ArcNode>();
          cflow_arc_out->set_placeName("state_cflow");
          cflow_arc_out->set_label("epsilon");
          transition->add_outArc(cflow_arc_out);

          // add transition to the unfolded model
          unfold_model->add_transition(transition);
        }
      }
    }

    /**************************************************************************
     * Handling CPN model
     **************************************************************************/

    // add parameters from CPN model to the unfolded model
    for (size_t i = 0; i < cpn_model->num_parameters(); i++) {
      unfold_model->add_parameter(cpn_model->get_parameter(i));
    }

    // add colors from CPN model to the unfolded model
    for (size_t i = 0; i < cpn_model->num_colors(); i++) {
      unfold_model->add_color(cpn_model->get_color(i));
    }

    // add functions from CPN model to the unfolded model
    for (size_t i = 0; i < cpn_model->num_functions(); i++) {
      unfold_model->add_function(cpn_model->get_function(i));
    }

    // add places from CPN model involded in the formula to the unfolded model
    std::vector<std::string> list_func;
    for (size_t i = 0; i < cpn_model->num_places(); i++) {
      HELENA::LnaNodePtr node = cpn_model->get_place(i);

      if (node->get_node_type() == HELENA::LnaNodeTypeComment) {
        current_submodel_name = get_model_name_from_comment(
            std::static_pointer_cast<HELENA::CommentNode>(node));
        // check if it is involded in the property
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_place(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
          // add if it has not been already done
          if (std::find(list_func.begin(), list_func.end(),
                        current_submodel_name) == list_func.end()) {
            HELENA::PlaceNodePtr cflow = std::make_shared<HELENA::PlaceNode>();
            cflow->set_name(current_submodel_name + "_cflow");
            cflow->set_domain("epsilon");
            if (current_submodel_name == "state") {
              cflow->set_init("epsilon");
            }
            unfold_model->add_place(cflow);
            list_func.push_back(current_submodel_name);
          }
        }
      } else if (node->get_node_type() == HELENA::LnaNodeTypePlace) {
        HELENA::PlaceNodePtr place =
            std::static_pointer_cast<HELENA::PlaceNode>(node);
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_place(place);
        }
      }
    }

    // add transitions from CPN model involded in the formula to the unfolded
    // model
    for (size_t i = 0; i < cpn_model->num_transitions(); i++) {
      HELENA::LnaNodePtr node = cpn_model->get_transition(i);

      if (node->get_node_type() == HELENA::LnaNodeTypeComment) {
        current_submodel_name = get_model_name_from_comment(
            std::static_pointer_cast<HELENA::CommentNode>(node));
        // check if it is involved in the formula
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_transition(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
        }
      } else if (node->get_node_type() == HELENA::LnaNodeTypeTransition) {
        HELENA::TransitionNodePtr transition =
            std::static_pointer_cast<HELENA::TransitionNode>(node);

        // check if it is involded in the formula
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          // add incoming arc to the transition
          if (transition->get_in_arc_by_name("S") != nullptr) {
            HELENA::ArcNodePtr cflow_arc_in =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_in->set_placeName(current_submodel_name + "_cflow");
            cflow_arc_in->set_label("epsilon");
            transition->add_inArc(cflow_arc_in);
          }

          // add outgoing arc to the transition
          if (transition->get_out_arc_by_name("S") != nullptr) {
            HELENA::ArcNodePtr cflow_arc_out =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_out->set_placeName("state_cflow");
            cflow_arc_out->set_label("epsilon");
            transition->add_outArc(cflow_arc_out);
          }

          unfold_model->add_transition(transition);
        }
      }
    }
  }

  return unfold_model;
}

HELENA::StructuredNetNodePtr Unfolder::unfoldModelWithFreeContext() {
  HELENA::StructuredNetNodePtr unfold_model =
      std::make_shared<HELENA::StructuredNetNode>();

  unfold_model->set_name(cpn_model->get_name());
  if (!unfolded_func.empty()) {
    std::string current_submodel_name;

    // add parameters from the CPN model to the unfolded model
    for (size_t i = 0; i < cpn_model->num_parameters(); i++) {
      unfold_model->add_parameter(cpn_model->get_parameter(i));
    }

    // add colors from the CPN model to the unfolded model
    for (size_t i = 0; i < cpn_model->num_colors(); i++) {
      unfold_model->add_color(cpn_model->get_color(i));
    }

    // add function from the CPN model to the unfolded model
    for (size_t i = 0; i < cpn_model->num_functions(); i++) {
      unfold_model->add_function(cpn_model->get_function(i));
    }

    // add the places involded in the formula to the unfolded model
    std::vector<std::string> list_func;
    for (size_t i = 0; i < cpn_model->num_places(); i++) {
      HELENA::LnaNodePtr node = cpn_model->get_place(i);
      if (node->get_node_type() == HELENA::LnaNodeTypeComment) {
        current_submodel_name = get_model_name_from_comment(
            std::static_pointer_cast<HELENA::CommentNode>(node));

        // check if it's involved in the property
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_place(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
          if (std::find(list_func.begin(), list_func.end(),
                        current_submodel_name) == list_func.end()) {
            list_func.push_back(current_submodel_name);
            HELENA::PlaceNodePtr cflow = std::make_shared<HELENA::PlaceNode>();
            cflow->set_name(current_submodel_name + "_cflow");
            cflow->set_domain("epsilon");
            if (current_submodel_name == "state") {
              cflow->set_init("epsilon");
            }
            unfold_model->add_place(cflow);
          }
        }
      } else if (node->get_node_type() == HELENA::LnaNodeTypePlace) {
        HELENA::PlaceNodePtr place =
            std::static_pointer_cast<HELENA::PlaceNode>(node);
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_place(place);
        }
      }
    }

    list_func.clear();

    // add the transitions involved in the formula to the unfolded model
    for (size_t i = 0; i < cpn_model->num_transitions(); i++) {
      HELENA::LnaNodePtr node = cpn_model->get_transition(i);
      if (node->get_node_type() == HELENA::LnaNodeTypeComment) {
        current_submodel_name = get_model_name_from_comment(
            std::static_pointer_cast<HELENA::CommentNode>(node));
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          unfold_model->add_transition(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
          if (std::find(list_func.begin(), list_func.end(),
                        current_submodel_name) == list_func.end()) {
            list_func.push_back(current_submodel_name);

            HELENA::TransitionNodePtr transition =
                std::make_shared<HELENA::TransitionNode>();
            transition->set_name(current_submodel_name);

            HELENA::ArcNodePtr cflow_arc_in =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_in->set_placeName("state_cflow");
            cflow_arc_in->set_label("epsilon");
            transition->add_inArc(cflow_arc_in);

            HELENA::ArcNodePtr cflow_arc_out =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_out->set_placeName(current_submodel_name + "_cflow");
            cflow_arc_out->set_label("epsilon");
            transition->add_outArc(cflow_arc_out);

            unfold_model->add_transition(transition);
          }
        } else {
          unfold_model->add_transition(std::make_shared<HELENA::CommentNode>(
              "\n/*\n * Function: " + current_submodel_name + "\n */\n"));
          if (std::find(list_func.begin(), list_func.end(),
                        current_submodel_name) == list_func.end()) {
            list_func.push_back(current_submodel_name);

            HELENA::TransitionNodePtr transition =
                std::make_shared<HELENA::TransitionNode>();
            transition->set_name(current_submodel_name);

            HELENA::ArcNodePtr cflow_arc_in =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_in->set_placeName("state_cflow");
            cflow_arc_in->set_label("epsilon");
            transition->add_inArc(cflow_arc_in);

            HELENA::ArcNodePtr cflow_arc_out =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_out->set_placeName("state_cflow");
            cflow_arc_out->set_label("epsilon");
            transition->add_outArc(cflow_arc_out);

            unfold_model->add_transition(transition);
          }
        }
      } else if (node->get_node_type() == HELENA::LnaNodeTypeTransition) {
        HELENA::TransitionNodePtr transition =
            std::static_pointer_cast<HELENA::TransitionNode>(node);
        if (std::find(unfolded_func.begin(), unfolded_func.end(),
                      current_submodel_name) != unfolded_func.end()) {
          if (transition->get_in_arc_by_name("S") != nullptr) {
            HELENA::ArcNodePtr cflow_arc_in =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_in->set_placeName(current_submodel_name + "_cflow");
            cflow_arc_in->set_label("epsilon");
            transition->add_inArc(cflow_arc_in);
          }

          if (transition->get_out_arc_by_name("S") != nullptr) {
            HELENA::ArcNodePtr cflow_arc_out =
                std::make_shared<HELENA::ArcNode>();
            cflow_arc_out->set_placeName("state_cflow");
            cflow_arc_out->set_label("epsilon");
            transition->add_outArc(cflow_arc_out);
          }

          unfold_model->add_transition(transition);
        }
      }
    }
  }

  return unfold_model;
}
