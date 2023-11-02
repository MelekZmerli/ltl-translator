#include "./DCR.hpp"

namespace DCR2CPN{
    
/** Get ID of the Event
 */
std::string Event::getID(){
    return id;
};
/** Get role of the Event
 */
std::string Event::getRoles(){
    return roles;
};
/** Get Data Type of the Event
 */
std::string Event::getDataType(){
    return dataType;
};
/** Get Parent of the Event
 */
std::string Event::getParent(){
    return parent;
};
/** Get label of the Event
 */
std::string Event::getLabel(){
    return label;
};
/** Get Type of the Event
 */
std::string Event::getType(){
    return type;
}
/** Get Type of the Relation
 */        
std::string Relation::getType(){
    return type;
}
/** Get source of the Relation
 */
std::string Relation::getSource(){
    return source;
}
/** Get target of the Relation
 */
std::string Relation::getTarget(){
    return target;
}
/** Get Guard of the relation
 */
std::string Relation::getGuard(){
    return guard;
}
/** Get Expression of the Relation
 */
std::string Relation::getDE(){
    return durationExpression;
}
    
/** Get source for the ERE
 */
Event  ERE::getSource(){
    return source;
}
/** Get Target for the ERE
 */
Event ERE::getTarget(){
    return target;
}
/** Get a list of relation
 */
std::vector<std::string> ERE::getLisRelation(){
    return listRelation;
}
/** Add a new relation
 */
void ERE::addRelation(std::string i){
    listRelation.push_back(i);   
};
/** add ERE to test
 */
void ERE::addToTest(int i ){
    test = test + std::to_string(i);
}
/** Get a test
 */
std::string ERE::getTest(){
    return test;
}
/** Set a text to test
 */
void ERE::setText(std::string t){
    test = t;
}
/** Set a list of relation
 */
void ERE::setListRelation(std::vector<std::string> ListRelation){
    listRelation = ListRelation;
}
/** Get exclusion to the vector
 */
std::vector<Event> Marking::getExclude(){
    return Exclude;
}
/** Get include from the vector
 */
std::vector<Event> Marking::getInclude(){
    return Include;
}
/** Get response from the vector
 */
std::vector<Event> Marking::getResponse(){
    return Response;
}
/** Set exlude to the vector
 */
void Marking::setExclude(std::vector<Event> exclude){
    Exclude = exclude;
}
/** Set include to the vector
 */
void Marking::setInclude(std::vector<Event> include){
    Include = include;
}
/** Set response to the vector
 */
void Marking::setResponse(std::vector<Event> response){
    Response = response;
}
/** Set event to the class
 */
void DCRClass::setEvent(std::vector<Event> ListEvent){
    listEvent = ListEvent;
}
/** Set marking to the class
 */
void DCRClass::setMarking(Marking InitMarking){
    initMarking = InitMarking;
}
/** Set ERE to the class
 */
void DCRClass::setERE(std::vector<ERE> ListERE){
    listERE = ListERE;
}
/** Get a list of Event
 */
std::vector<Event> DCRClass::getListEvent(){
    return listEvent;
}
/** Get marking of the class
 */
Marking DCRClass::getMarking(){
    return initMarking;
}
/** Get ERE from the class
 */
std::vector<ERE> DCRClass::getERE(){
    return listERE;
}
/** Get the description
 */
std::string DCRClass::description(){
    return  "";
}

}
