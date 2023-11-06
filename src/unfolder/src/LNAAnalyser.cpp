#include "LNAAnalyser.hpp"

namespace HELENA {

/** Get substrings blocked by '{' and '}' characters in multilines
 *
 * example:
 *      string input = "hello world { some comment\n some comment }";
 *      string output = handleElementBody(output);
 *      output == " some comment\n some comment ";
 */
string handleElementBody(list<string>::iterator& _iter,
                         list<string>::iterator _end_iter) {
  while (_iter != _end_iter && (*_iter).find("{") == string::npos) {
    ++_iter;
  }

  stringstream _str;
  size_t st_sub = 0;
  size_t ed_sub = 0;
  int level = 0;

  do {
    if ((*_iter).find("{") != string::npos) {
      if (level == 0) {
        st_sub = (*_iter).find("{");
      }
      level++;
    }
    if ((*_iter).find("}") != string::npos) {
      level--;
      if (level == 0) {
        ed_sub -= ((*_iter).length() + 1 - (*_iter).find("}"));
      }
    }
    ed_sub += (*_iter).length() + 1;
    _str << *_iter << '\n';

    ++_iter;
  } while (_iter != _end_iter && level != 0);
  --_iter;

  return _str.str().substr(st_sub + 2, ed_sub - 3 - st_sub);
}

/** Get all arc node in input block
 */
vector<ArcNodePtr> handleArcs(list<string>::iterator& _iter,
                              list<string>::iterator _end_iter) {
  vector<ArcNodePtr> result;

  string _body = handleElementBody(_iter, _end_iter);
  vector<string> arcs = split(_body, ";");

  for (auto it = arcs.begin(); it != arcs.end(); ++it) {
    vector<string> arc_el = split_ex(*it, ":", 2);
    if (arc_el.size() == 2) {
      ArcNodePtr arc = make_shared<ArcNode>();
      arc->set_placeName(removeNoneAlnum(arc_el[0]));
      arc->set_label(trim_copy(arc_el[1]));
      result.push_back(arc);
    }
  }
  return result;
}

/** Returns an object of the TransitionNode class corresponding to a block code
 */
TransitionNodePtr handleTransition(list<string>::iterator& _iter,
                                   list<string>::iterator _end_iter) {
  string token = get_first_alpha_only_string(*_iter);
  if (token == TRANSITION_TOKEN) {
    TransitionNodePtr transition = make_shared<TransitionNode>();

    string transition_name =
        removeNoneAlnum(retrieve_string_element(*_iter, 1, " "));
    transition->set_name(transition_name);

    while (_iter != _end_iter && (*_iter).find("{") == string::npos) {
      ++_iter;
    }

    std::string temp;
    do {
      string keyword = get_first_alpha_only_string(*_iter);
      if (keyword == IN_TOKEN) {
        vector<ArcNodePtr> arcs = handleArcs(_iter, _end_iter);
        for (auto it = arcs.begin(); it != arcs.end(); ++it) {
          transition->add_inArc(*it);
        }
      } else if (keyword == OUT_TOKEN) {
        vector<ArcNodePtr> arcs = handleArcs(_iter, _end_iter);
        for (auto it = arcs.begin(); it != arcs.end(); ++it) {
          transition->add_outArc(*it);
        }
      } else if (keyword == LET_TOKEN) {
        string let = handleElementBody(_iter, _end_iter);
        transition->add_let(let);
      } else if (keyword == GUARD_TOKEN) {
        std::cout << *_iter << "\n";
        string guard = trim_copy(split_ex(*_iter, ":", 2)[1]);
        transition->set_guard(guard);
      } else if (keyword == PRIORITY_TOKEN) {
        string priority = trim_copy(split_ex(*_iter, ":", 2)[1]);
        transition->set_priority(priority);
      }

      ++_iter;
      temp = *_iter;
      trim_ex(temp);
    } while (_iter != _end_iter && temp[0] != '}');
    --_iter;
    return transition;
  }
  return nullptr;
}

/** Returns an object of the PlaceNode class corresponding to a block code
 */
PlaceNodePtr handlePlace(list<string>::iterator& _iter,
                         list<string>::iterator _end_iter) {
  string token = get_first_alpha_only_string(*_iter);
  if (token == PLACE_TOKEN) {
    PlaceNodePtr place = make_shared<PlaceNode>();

    string place_name =
        removeNoneAlnum(retrieve_string_element(*_iter, 1, " "));
    place->set_name(place_name);

    string place_body = handleElementBody(_iter, _end_iter);
    vector<string> eles = split(place_body, ";");

    for (auto it = eles.begin(); it != eles.end(); ++it) {
      trim_ex(*it);
      vector<string> p_tokens = split_ex(*it, ":", 2);
      if (p_tokens.size() == 2) {
        rtrim_ex(p_tokens[0]);
        ltrim_ex(p_tokens[1]);

        if (p_tokens[0] == DOM_TOKEN) {
          place->set_domain(p_tokens[1]);
        } else if (p_tokens[0] == INIT_TOKEN) {
          place->set_init(p_tokens[1]);
        } else if (p_tokens[0] == CAPACITY_TOKEN) {
          place->set_capacity(p_tokens[1]);
        } else if (p_tokens[0] == TYPE_TOKEN) {
          place->set_type(p_tokens[1]);
        }
      }
    }

    return place;
  }
  return nullptr;
}

/** Returns an object of the ColorNode class corresponding to a block code
 */
ColorNodePtr handleColor(list<string>::iterator& _iter,
                         list<string>::iterator _end_iter) {
  string token = get_first_alpha_only_string(*_iter);
  if (token == TYPE_TOKEN) {
    ColorNodePtr color;

    vector<string> color_def = split_ex(split_ex(*_iter, " ", 2)[1], ":", 2);

    string color_name = removeNoneAlnum(color_def[0]);

    string color_typedef = color_def[1];
    trim_ex(color_typedef);

    string color_type = get_first_alpha_only_string(color_typedef);
    if (color_type == RANGE_TOKEN) {
      color = make_shared<ColorNode>();
      color->set_name(color_name);
      color_typedef.erase(
          remove(color_typedef.begin(), color_typedef.end(), ';'),
          color_typedef.end());
      color->set_typeDef(color_typedef);
    } else if (color_type == STRUCT_TOKEN) {
      StructColorNodePtr struct_color = make_shared<StructColorNode>();
      struct_color->set_name(color_name);

      string struct_body = handleElementBody(_iter, _end_iter);
      vector<string> eles = split(struct_body, ";");
      for (auto it = eles.begin(); it != eles.end(); ++it) {
        vector<string> st_tokens = split_ex(trim_copy(*it), " ", 2);
        if (st_tokens.size() == 2) {
          trim_ex(st_tokens[0]);
          trim_ex(st_tokens[1]);

          ComponentNodePtr comp = make_shared<ComponentNode>();
          comp->set_name(st_tokens[1]);
          comp->set_type(st_tokens[0]);
          struct_color->add_component(comp);
        }
      }

      color = static_pointer_cast<ColorNode>(struct_color);
    } else if (color_type == LIST_TOKEN) {
      ListColorNodePtr list_color = make_shared<ListColorNode>();
      list_color->set_name(color_name);

      string index_type =
          removeNoneAlnum(substr_by_edge(color_typedef, "[", "]"));
      list_color->set_index_type(index_type);

      vector<string> eles = split(color_typedef, " ");
      int cout = 0;
      string pre_str;
      for (auto it = eles.begin(); it != eles.end(); ++it) {
        trim_ex(*it);
        if ((*it).length() > 0) {
          if (*it == OF_TOKEN) {
            pre_str = OF_TOKEN;
          } else if (*it == WITH_TOKEN) {
            pre_str = WITH_TOKEN;
          } else if (*it == CAPACITY_TOKEN) {
            pre_str = CAPACITY_TOKEN;
          } else {
            if (pre_str == OF_TOKEN) {
              string element_type = removeNoneAlnum(*it);
              list_color->set_element_type(element_type);
            } else if (pre_str == CAPACITY_TOKEN) {
              string capacity = removeNoneAlnum(*it);
              list_color->set_capacity(capacity);
            }
          }
        }
      }

      color = static_pointer_cast<ColorNode>(list_color);
    }

    return color;
  } else if (token == SUBTYPE_TOKEN) {
    SubColorNodePtr sub_color = make_shared<SubColorNode>();

    vector<string> sub_color_def =
        split_ex(split_ex(*_iter, " ", 2)[1], ":", 2);

    string sub_color_name = removeNoneAlnum(sub_color_def[0]);
    sub_color->set_name(sub_color_name);
    string sub_color_typedef = sub_color_def[1];
    trim_ex(sub_color_typedef);

    ColorNodePtr color = make_shared<ColorNode>();
    vector<string> color_def = split_ex(sub_color_typedef, " ", 2);
    string color_name = color_def[0];
    string color_typedef = color_def[1];

    string color_type = get_first_alpha_only_string(color_typedef);
    if (color_type == RANGE_TOKEN) {
      color->set_name(color_name);
      color_typedef.erase(
          remove(color_typedef.begin(), color_typedef.end(), ';'),
          color_typedef.end());
      sub_color->set_typeDef(color_typedef);
    }
    sub_color->set_supColor(color);

    return std::static_pointer_cast<ColorNode>(sub_color);
  }
  return nullptr;
}

/** Returns an object of the FunctionNode class corresponding to a block code
 */
FunctionNodePtr handleFunction(list<string>::iterator& _iter,
                               list<string>::iterator _end_iter) {
  string token = get_first_alpha_only_string(*_iter);
  if (token == FUNCTION_TOKEN) {
    FunctionNodePtr function = make_shared<FunctionNode>();

    string func_header = split_ex(*_iter, " ", 2)[1];
    trim_ex(func_header);

    string func_name = get_first_alpha_only_string(func_header);
    function->set_name(func_name);

    string param_def = substr_by_edge(func_header, "(", ")");
    trim_ex(param_def);
    if (param_def.length() > 0) {
      vector<string> params = split(param_def, ",");
      for (auto it = params.begin(); it != params.end(); ++it) {
        vector<string> param = split_ex(trim_copy(*it), " ", 2);
        trim_ex(param[0]);
        trim_ex(param[1]);

        ParamNodePtr fparam = make_shared<ParamNode>();
        fparam->set_name(param[1]);
        fparam->set_type(param[0]);
        function->add_parameter(fparam);
      }
    }

    string func_return_type =
        get_first_alpha_only_string(split_ex(func_header, "->", 2)[1]);
    function->set_returnType(func_return_type);

    string func_body = handleElementBody(_iter, _end_iter);
    function->set_body(func_body);

    return function;
  }
  return nullptr;
}

}  // namespace HELENA
