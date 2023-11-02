#include "dcr2cpn.hpp"

#include <fstream>
#include <iostream>
#include <rapidxml.hpp>

#include "utils.hpp"

using namespace HELENA;
namespace DCR2CPN {

bool isSubOf2(const std::string& ParentNameInput,
              const std::string& EventNameInput,
              std::vector<DCR2CPN::Event> listEvent) {
  std::string ParentName = ParentNameInput;
  std::string EventName = EventNameInput;
  if (ParentNameInput == "")
    return false;
  else {
    for (auto itrEvent = listEvent.begin(); itrEvent != listEvent.end();
         itrEvent++) {
      DCR2CPN::Event e = *itrEvent;
      if (e.getID() == EventName) {
        if (e.getParent() == ParentNameInput) {
          return true;
        } else {
          return (isSubOf2(ParentNameInput, e.getParent(), listEvent));
        }
      }
    }
  }
  return false;
}

/**
 * The class to read a DCR xml input file to an object of DCR
 * @date Sep 2021
 */
DCRClass readDCRFromXML(const std::string& DCR_XML_FILE) {
  /**
   * Declare the variables of the class
   */
  rapidxml::xml_document<> doc;
  rapidxml::xml_node<>* root_node = NULL;
  std::vector<Event> listEvent;
  std::vector<Relation> listRelation;

  /** Read data from the xml file
   */
  std::ifstream theFile(DCR_XML_FILE);
  std::vector<char> buffer((std::istreambuf_iterator<char>(theFile)),
                           std::istreambuf_iterator<char>());
  buffer.push_back('\0');

  /** Parse the buffer
   */
  doc.parse<0>(&buffer[0]);
  root_node = doc.first_node("DCRModel");
  int nEvent = 0;
  /** Take a name of an attribute of Events by using iterator to skim each
   * sub_node of node that have name Events in XML
   */
  for (rapidxml::xml_node<>* events_node = root_node->first_node("events");
       events_node; events_node = events_node->next_sibling()) {
    std::string id, labels, roles, datatype, parent, type;
    if (events_node->first_node("id") != nullptr) {
      id = events_node->first_node("id")->value();
    } else {
      id = "";
    }
    if (events_node->first_node("label") != nullptr) {
      labels = events_node->first_node("label")->value();
    } else {
      labels = "";
    }
    if (events_node->first_node("roles") != nullptr) {
      roles = events_node->first_node("roles")->value();
    } else {
      roles = "";
    }
    if (events_node->first_node("datatype") != nullptr) {
      datatype = events_node->first_node("datatype")->value();
    } else {
      datatype = "";
    }
    if (events_node->first_node("parent") != nullptr) {
      parent = events_node->first_node("parent")->value();
    } else {
      parent = "";
    }
    if (events_node->first_node("type") != nullptr) {
      type = events_node->first_node("type")->value();
    } else {
      type = "";
    }
    if (id != "") {
      listEvent.push_back(Event(id, labels, roles, datatype, parent, type));
    }
  }
  int numofEvent = 0, numOfRalation = 0;
  for (auto itr = listEvent.begin(); itr != listEvent.end(); itr++) {
    numofEvent++;
  }
  /** Take a name of an attribute of Rules by using iterator to skim each
   * sub_node of node that have name Rules in XML
   */
  for (rapidxml::xml_node<>* rule_node = root_node->first_node("rules");
       rule_node; rule_node = rule_node->next_sibling()) {
    std::string type, source, target, guard, de;
    if (rule_node->first_node("type") != nullptr) {
      type = rule_node->first_node("type")->value();
    } else {
      type = "";
    }
    if (rule_node->first_node("source") != nullptr) {
      source = rule_node->first_node("source")->value();
    } else {
      source = "";
    }
    if (rule_node->first_node("target") != nullptr) {
      target = rule_node->first_node("target")->value();
    } else {
      target = "";
    }
    if (rule_node->first_node("durationexpression") != nullptr) {
      de = rule_node->first_node("durationexpression")->value();
    } else {
      de = "";
    }
    if (rule_node->first_node("guard") != nullptr) {
      guard = rule_node->first_node("guard")->value();
    } else {
      guard = "";
    }
    if (type != "") {
      listRelation.push_back(Relation(type, source, target, guard, de));
    }
  }

  /** Declare a vector for ERE
   */
  std::vector<ERE> listERE;

  /** Add all couples [E-E](Event-i <> Event-J to std::vector (2 Events must
   * have differents ID)
   */
  for (auto itr1 = listEvent.begin(); itr1 != listEvent.end(); itr1++) {
    for (auto itr2 = listEvent.begin(); itr2 != listEvent.end(); itr2++) {
      Event source = *itr1;
      Event target = *itr2;
      if (source.getID() == target.getID()) {
        continue;
      } else {
        std::vector<std::string> nilVector;
        listERE.push_back(ERE(source, target, nilVector));
      }
    }
  }

  /** Iterate all Relations in the vector
   */
  for (auto itrRelation = listRelation.begin();
       itrRelation != listRelation.end(); itrRelation++) {
    Relation rel = *itrRelation;
    std::string sourceName = rel.getSource();
    std::string targetName = rel.getTarget();
    Event source, target;
    int count = 0;
    /** Iterate all Events of list Events to take the Event Source and Event
     * Target
     *
     */
    for (auto itrEvent = listEvent.begin(); itrEvent != listEvent.end();
         itrEvent++) {
      if (itrEvent->getID() == targetName) {
        target = *itrEvent;
        count++;
      }
      if (itrEvent->getID() == sourceName) {
        source = *itrEvent;
        count++;
      }
      if (count == 2) {
        break;
      }
    }
    /** Iterate all EREs in the list ERE
     */
    for (auto itrERE = listERE.begin(); itrERE != listERE.end(); itrERE++) {
      ERE ere = *itrERE;
      /** Check if current index ERE have Event-Source and Event-Target same of
       * Relation.
       */
      if (ere.getSource().getID() == sourceName &&
          ere.getTarget().getID() == targetName) {
        itrERE->setText(itrERE->getTest() + " ; " + itrRelation->getType());
        std::vector<std::string> a = itrERE->getLisRelation();
        a.push_back(itrRelation->getType());
        itrERE->setListRelation(a);
        break;
      }
    }
    /** If 2 Events is nesting, add Relations to all EREs have Event-Soure and
     * Event-Target that is a subevent of this 2 nesting Events
     */
    if (source.getType() == "nesting" && target.getType() == "nesting") {
      for (auto itrERE = listERE.begin(); itrERE != listERE.end(); itrERE++) {
        ERE ere = *itrERE;
        if (isSubOf2(sourceName, ere.getSource().getID(), listEvent) &&
            isSubOf2(targetName, ere.getTarget().getID(), listEvent)) {
          std::vector<std::string> a = itrERE->getLisRelation();
          a.push_back(itrRelation->getType());
          itrERE->setListRelation(a);
          itrERE->setText(itrERE->getTest() + " ; " + itrRelation->getType());
        }
      }
    }
    /** Check if one of 2 Events is nesting
     */
    else if (source.getType() == "nesting") {
      for (auto itrERE = listERE.begin(); itrERE != listERE.end(); itrERE++) {
        ERE ere = *itrERE;
        if (isSubOf2(sourceName, ere.getSource().getID(), listEvent) &&
            ere.getTarget().getID() == targetName) {
          std::vector<std::string> a = itrERE->getLisRelation();
          a.push_back(itrRelation->getType());
          itrERE->setListRelation(a);
          itrERE->setText(itrERE->getTest() + " ; " + itrRelation->getType());
        }
      }
    } else if (target.getType() == "nesting") {
      for (auto itrERE = listERE.begin(); itrERE != listERE.end(); itrERE++) {
        ERE ere = *itrERE;
        if (ere.getSource().getID() == sourceName &&
            isSubOf2(targetName, ere.getTarget().getID(), listEvent)) {
          std::vector<std::string> a = itrERE->getLisRelation();
          a.push_back(itrRelation->getType());
          itrERE->setListRelation(a);
          itrERE->setText(itrERE->getTest() + " ; " + itrRelation->getType());
        }
      }
    }
  }

  std::vector<Event> Exclude;
  std::vector<Event> Response;
  Marking initMarking(Exclude, listEvent, Response);
  DCRClass myDCRClass(listEvent, initMarking, listERE);
  return myDCRClass;
}

/** Declare the getters of the class
 */
std::string SubNet::get_name() { return name; }

std::string SubNet::get_id() { return id; }
/** Add the executed parametters to the subnet
 */
void SubNet::add_executecvparams(const std::string& param) {
  executeCVParams.push_back(param);
}

/** Add the included parametters to the subnet
 */
void SubNet::add_includecvparams(const std::string& param) {
  includeCVParams.push_back(param);
}

/** Add the response parametters to the subnet
 */
void SubNet::add_responsecvparams(const std::string& param) {
  responseCVParams.push_back(param);
}

/** Add the milestone parametter to the subnet
 */
void SubNet::add_cmilestone(const std::string& param) {
  cMilestone.push_back(param);
}
/** Add the condition parametter to the subnet
 */
void SubNet::add_ccondition(const std::string& param) {
  cCondition.push_back(param);
}

/**
 * @return a transition with:
 *
 *      name: 'transition.name'
 *
 *      in arcs: marking: <(execute,response,include)>;
 *               cflow: epsilon;
 *
 *      out arc: marking: <(new_execute,new_response,new_include)>
 *               cflow: epsilon;
 *
 *           -new_execute: add 1 to position 'transition.id' in execute
 *           -new_response: based on response relations
 *           -new_include: based on include and exclude relations
 *
 *      guard: include['transition.id'] = 1 and new_condition
 *
 *           -new_condition: based on condition and milestone relations
 */
TransitionNodePtr SubNet::createTransition() {
  TransitionNodePtr trans = std::make_shared<TransitionNode>();
  trans->set_name(name);

  ArcNodePtr marking_in = std::make_shared<ArcNode>();
  marking_in->set_placeName("marking");
  marking_in->set_label("<(execute,response,include)>");
  trans->add_inArc(marking_in);

  std::stringstream out_arc_label;
  out_arc_label << "<(";
  if (executeCVParams.size() > 0) {
    out_arc_label << "cvalue(execute,|";
    for (int i = 0; i < executeCVParams.size() - 1; i++) {
      out_arc_label << executeCVParams[i] << ",";
    }
    out_arc_label << executeCVParams[executeCVParams.size() - 1];
    out_arc_label << "|)";
  } else {
    out_arc_label << "execute";
  }
  out_arc_label << ",";

  if (responseCVParams.size() > 0) {
    out_arc_label << "cvalue(response,|";
    for (int i = 0; i < responseCVParams.size() - 1; i++) {
      out_arc_label << responseCVParams[i] << ",";
    }
    out_arc_label << responseCVParams[responseCVParams.size() - 1];
    out_arc_label << "|)";
  } else {
    out_arc_label << "response";
  }
  out_arc_label << ",";

  if (includeCVParams.size() > 0) {
    out_arc_label << "cvalue(include,|";
    for (int i = 0; i < includeCVParams.size() - 1; i++) {
      out_arc_label << includeCVParams[i] << ",";
    }
    out_arc_label << includeCVParams[includeCVParams.size() - 1];
    out_arc_label << "|)";
  } else {
    out_arc_label << "include";
  }
  out_arc_label << ")>";

  ArcNodePtr marking_out = std::make_shared<ArcNode>();
  marking_out->set_placeName("marking");
  marking_out->set_label(out_arc_label.str());
  trans->add_outArc(marking_out);

  std::stringstream guard_string;
  guard_string << "(include[" << id << "] = 1)";

  if (cCondition.size() > 0) {
    guard_string << " and (confirm_condition(|";
    for (int i = 0; i < cCondition.size() - 1; i++) {
      guard_string << cCondition[i] << ",";
    }
    guard_string << cCondition[cCondition.size() - 1];
    guard_string << "|) = 1)";
  }

  if (cMilestone.size() > 0) {
    guard_string << " and (confirm_milestone(|";
    for (int i = 0; i < cMilestone.size() - 1; i++) {
      guard_string << cMilestone[i] << ",";
    }
    guard_string << cMilestone[cMilestone.size() - 1];
    guard_string << "|) = 1)";
  }
  guard_string << ";";
  trans->set_guard(guard_string.str());

  return trans;
}

/** Add a subnet to the collection
 */
void Dcr2CpnTranslator::add_subnet(const std::string& subnet_name,
                                   SubNetPtr _subnet) {
  if (subnets.find(subnet_name) == subnets.end()) {
    subnets[subnet_name] = _subnet;
  }
}

/** Get a subnet by its name
 */
SubNetPtr Dcr2CpnTranslator::get_subnet_by_name(
    const std::string& subnet_name) {
  if (subnets.find(subnet_name) != subnets.end()) {
    return subnets[subnet_name];
  }
  return nullptr;
}
/** get the subnet ID by its name
 */
std::string Dcr2CpnTranslator::get_subnet_id(const std::string& subnet_name) {
  if (subnets.find(subnet_name) != subnets.end()) {
    return subnets[subnet_name]->get_id();
  }
  return "-1";
}

/**
 * @return a pointer to NetNode class
 *   NetNode class is a class that handle all information about a helena code
 * file.
 */
StructuredNetNodePtr Dcr2CpnTranslator::translate() {
  net = std::make_shared<StructuredNetNode>();
  net->set_name("test");

  generateInitColours();
  generateInitFunctions();
  generateInitPlaces();

  std::map<std::string, bool> events_self_response;
  std::vector<SubNetPtr> vsubnets;
  std::vector<Event> dcr_events = dcrClass.getListEvent();

  /** Create a subnet corresponding to an event in the dcr events
   */
  for (int i = 0; i < dcr_events.size(); i++) {
    std::string subnet_name = removeNoneAlnum(dcr_events[i].getID());
    events_self_response[subnet_name] = false;

    SubNetPtr subnet = std::make_shared<SubNet>(subnet_name, std::to_string(i));
    add_subnet(subnet_name, subnet);
    vsubnets.push_back(subnet);
  }

  /** Loop through the EREs to get the relations between two events, then add
   * specific parameters to specific subnets based on this condition
   */
  std::vector<ERE> dcr_ere = dcrClass.getERE();
  for (auto it = dcr_ere.begin(); it != dcr_ere.end(); it++) {
    SubNetPtr eventSource =
        get_subnet_by_name(removeNoneAlnum(it->getSource().getID()));
    SubNetPtr eventDest =
        get_subnet_by_name(removeNoneAlnum(it->getTarget().getID()));
    if (eventSource != nullptr && eventDest != nullptr) {
      std::vector<std::string> listRelation = it->getLisRelation();
      for (auto rel = listRelation.begin(); rel != listRelation.end(); rel++) {
        if ((*rel).compare("include") == 0) {
          eventSource->add_includecvparams("{" + eventDest->get_id() + ",1}");
        } else if ((*rel).compare("exclude") == 0) {
          eventSource->add_includecvparams("{" + eventDest->get_id() + ",0}");
        } else if ((*rel).compare("response") == 0) {
          if (eventSource->get_name().compare(eventDest->get_name()) == 0) {
            events_self_response[eventSource->get_name()] = true;
          }
          eventSource->add_responsecvparams("{" + eventDest->get_id() + ",1}");
        } else if ((*rel).compare("condition") == 0) {
          eventDest->add_ccondition("{include[" + eventSource->get_id() +
                                    "],execute[" + eventSource->get_id() +
                                    "]}");
        } else if ((*rel).compare("milestone") == 0) {
          eventDest->add_cmilestone("{include[" + eventSource->get_id() +
                                    "],response[" + eventSource->get_id() +
                                    "]}");
        }
      }
    }
  }

  /** Check if the event has a response relation to itself
   */
  for (auto it = events_self_response.begin(); it != events_self_response.end();
       it++) {
    SubNetPtr event = get_subnet_by_name(it->first);
    if (!(it->second)) {
      event->add_responsecvparams("{" + event->get_id() + ",0}");
    }
    event->add_executecvparams("{" + event->get_id() + ",1}");
  }

  /** Get transitions from subnet and add it to a NetNode
   */
  for (auto it = vsubnets.begin(); it != vsubnets.end(); ++it) {
    TransitionNodePtr trans = (*it)->createTransition();
    net->add_transition(std::make_shared<CommentNode>(
        "\n/*\n * Function: " + trans->get_name() + "\n */\n"));
    net->add_transition(trans);
  }

  return net;
}
/** Generate the initial colours for the net
 */
void Dcr2CpnTranslator::generateInitColours() {
  ParameterNodePtr n_param = std::make_shared<ParameterNode>();
  n_param->set_name("N");
  n_param->set_number(std::to_string(dcrClass.getListEvent().size()));
  net->add_parameter(n_param);

  ColorNodePtr boolean = std::make_shared<ColorNode>();
  boolean->set_name("boolean");
  boolean->set_typeDef("range 0 .. 1");
  net->add_color(boolean);

  ColorNodePtr count = std::make_shared<ColorNode>();
  count->set_name("count");
  count->set_typeDef("range 0 .. N");
  net->add_color(count);

  SubColorNodePtr event_id = std::make_shared<SubColorNode>(count);
  event_id->set_name("event_id");
  event_id->set_typeDef("range 0 .. (count'last-1)");
  net->add_color(std::static_pointer_cast<ColorNode>(event_id));

  ListColorNodePtr marking_value = std::make_shared<ListColorNode>();
  marking_value->set_name("marking_value");
  marking_value->set_index_type("event_id");
  marking_value->set_element_type("boolean");
  marking_value->set_capacity("N");
  net->add_color(std::static_pointer_cast<ColorNode>(marking_value));

  StructColorNodePtr mvalue = std::make_shared<StructColorNode>();
  mvalue->set_name("mvalue");

  ComponentNodePtr id = std::make_shared<ComponentNode>();
  id->set_name("id");
  id->set_type("event_id");
  mvalue->add_component(id);

  ComponentNodePtr vl = std::make_shared<ComponentNode>();
  vl->set_name("vl");
  vl->set_type("boolean");
  mvalue->add_component(vl);
  net->add_color(std::static_pointer_cast<ColorNode>(mvalue));

  ListColorNodePtr vchange = std::make_shared<ListColorNode>();
  vchange->set_name("vchange");
  vchange->set_index_type("event_id");
  vchange->set_element_type("mvalue");
  vchange->set_capacity("N");
  net->add_color(std::static_pointer_cast<ColorNode>(vchange));

  StructColorNodePtr cvalue = std::make_shared<StructColorNode>();
  cvalue->set_name("cvalue");

  ComponentNodePtr cv1 = std::make_shared<ComponentNode>();
  cv1->set_name("cv1");
  cv1->set_type("boolean");
  cvalue->add_component(cv1);

  ComponentNodePtr cv2 = std::make_shared<ComponentNode>();
  cv2->set_name("cv2");
  cv2->set_type("boolean");
  cvalue->add_component(cv2);
  net->add_color(std::static_pointer_cast<ColorNode>(cvalue));

  ListColorNodePtr vcondition = std::make_shared<ListColorNode>();
  vcondition->set_name("vcondition");
  vcondition->set_index_type("event_id");
  vcondition->set_element_type("cvalue");
  vcondition->set_capacity("N");
  net->add_color(std::static_pointer_cast<ColorNode>(vcondition));
}

/** Generate the initial places for the net
 */
void Dcr2CpnTranslator::generateInitPlaces() {
  PlaceNodePtr marking = std::make_shared<PlaceNode>();
  marking->set_name("marking");
  marking->set_domain("marking_value*marking_value*marking_value");

  int num = dcrClass.getListEvent().size();

  std::string exer, inc;
  for (int i = 0; i < num - 1; i++) {
    exer += "0,";
    inc += "1,";
  }
  exer += "0";
  inc += "1";

  marking->set_init("<(|" + exer + "|,|" + exer + "|,|" + inc + "|)>");
  net->add_place(
      std::make_shared<CommentNode>("\n/*\n * Function: state\n */\n"));
  net->add_place(marking);
}
/** Generate the initial functions for the net
 */
void Dcr2CpnTranslator::generateInitFunctions() {
  FunctionNodePtr cvalue = std::make_shared<FunctionNode>();
  cvalue->set_name("cvalue");
  cvalue->set_returnType("marking_value");
  ParamNodePtr mv = std::make_shared<ParamNode>();
  mv->set_name("mv");
  mv->set_type("marking_value");
  cvalue->add_parameter(mv);
  ParamNodePtr lc = std::make_shared<ParamNode>();
  lc->set_name("lc");
  lc->set_type("vchange");
  cvalue->add_parameter(lc);
  cvalue->set_body(
      "\tmarking_value m := empty;\n\tfor(v in mv){\n\t\tm := m & "
      "v;\n\t}\n\tfor(v in lc){\n\t\tm[v.id] := v.vl;\n\t}\n\treturn m;");
  net->add_function(cvalue);

  FunctionNodePtr confirm_condition = std::make_shared<FunctionNode>();
  confirm_condition->set_name("confirm_condition");
  confirm_condition->set_returnType("boolean");
  ParamNodePtr vc_c = std::make_shared<ParamNode>();
  vc_c->set_name("vc");
  vc_c->set_type("vcondition");
  confirm_condition->add_parameter(vc_c);
  confirm_condition->set_body(
      "\tboolean ret := 1;\n\tfor(v in vc){\n\t\tif(v.cv1 = 1 and v.cv2 = 0) "
      "ret := 0;\n\t}\n\treturn ret;");
  net->add_function(confirm_condition);

  FunctionNodePtr confirm_milestone = std::make_shared<FunctionNode>();
  confirm_milestone->set_name("confirm_milestone");
  confirm_milestone->set_returnType("boolean");
  ParamNodePtr vc_m = std::make_shared<ParamNode>();
  vc_m->set_name("vc");
  vc_m->set_type("vcondition");
  confirm_milestone->add_parameter(vc_m);
  confirm_milestone->set_body(
      "\tboolean ret := 1;\n\tfor(v in vc){\n\t\tif(v.cv1 = 1 and v.cv2 = 1) "
      "ret := 0;\n\t}\n\treturn ret;");
  net->add_function(confirm_milestone);
}

}  // namespace DCR2CPN
