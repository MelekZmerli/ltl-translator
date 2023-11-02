#ifndef HELENA_LNAANALYSER_H_
#define HELENA_LNAANALYSER_H_

#include "./Helena.hpp"

namespace HELENA{

ParameterNodePtr handleParameter(list<string>::iterator& _iter, list<string>::iterator _end_iter);

TransitionNodePtr handleTransition(list<string>::iterator& _iter, list<string>::iterator _end_iter);

PlaceNodePtr handlePlace(list<string>::iterator& _iter, list<string>::iterator _end_iter);

ColorNodePtr handleColor(list<string>::iterator& _iter, list<string>::iterator _end_iter);

FunctionNodePtr handleFunction(list<string>::iterator& _iter, list<string>::iterator _end_iter);

string handleElementBody(list<string>::iterator& _iter, list<string>::iterator _end_iter);

vector<ArcNodePtr> handleArcs(list<string>::iterator& _iter, list<string>::iterator _end_iter);
} // namespace HELENA

#endif