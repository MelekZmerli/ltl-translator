#ifndef HELENA_LNAANALYSER_H_
#define HELENA_LNAANALYSER_H_

#include <list>
#include <string>
#include <vector>

#include "Helena.hpp"

namespace HELENA {

ParameterNodePtr handleParameter(std::list<std::string>::iterator& _iter,
                                 std::list<std::string>::iterator _end_iter);

TransitionNodePtr handleTransition(std::list<std::string>::iterator& _iter,
                                   std::list<std::string>::iterator _end_iter);

PlaceNodePtr handlePlace(std::list<std::string>::iterator& _iter,
                         std::list<std::string>::iterator _end_iter);

ColorNodePtr handleColor(std::list<std::string>::iterator& _iter,
                         std::list<std::string>::iterator _end_iter);

FunctionNodePtr handleFunction(std::list<std::string>::iterator& _iter,
                               std::list<std::string>::iterator _end_iter);

std::string handleElementBody(std::list<std::string>::iterator& _iter,
                              std::list<std::string>::iterator _end_iter);

std::vector<ArcNodePtr> handleArcs(std::list<std::string>::iterator& _iter,
                                   std::list<std::string>::iterator _end_iter);
}  // namespace HELENA

#endif