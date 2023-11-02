#ifndef DCR2CPN_DCR_H_
#define DCR2CPN_DCR_H_

#include<vector>
#include<string>

namespace DCR2CPN{

enum EnumRelations{
    condition,
    response,
    include,
    exclude,
    milestone
};

class Event{
    public:
        Event(){};
        explicit Event(const std::string& _id, const std::string&  _label, const std::string&  _roles, const std::string&  _datatype, const std::string&  _parent ,const std::string&  _type): 
                    id(_id), label(_label), roles(_roles), dataType(_datatype), parent(_parent), type(_type) {}
        std::string getID();
        std::string getRoles();
        std::string getDataType();
        std::string getParent();
        std::string getLabel();
        std::string getType();
        
    private:
        std::string id;
        std::string label;
        std::string roles;
        std::string dataType;
        std::string parent;
        std::string type;

};

class Relation
{
private:
    std::string type;
    std::string source;
    std::string target;
    std::string guard;
    std::string durationExpression;
    
public:
    Relation(){};
    explicit Relation(const std::string& _type,const std::string& _source, const std::string& _target, const std::string& _guard, const std::string& _durationExpression):
                    type(_type), source(_source), target(_target), guard(_guard), durationExpression(_durationExpression) {}
    std::string getType();
    std::string getSource();
    std::string getTarget();
    std::string getGuard();
    std::string getDE();
    
};


class ERE{
    public:
        ERE(){};
        explicit ERE(Event _source, Event _target, std::vector<std::string> _relations):
                source(_source), target(_target), listRelation(_relations) {}
        Event  getSource();
        Event getTarget();
        std::vector<std::string> getLisRelation();
        void addRelation(std::string i);
        void addToTest(int i );
        std::string getTest();
        void setText(std::string t);
        void setListRelation(std::vector<std::string> ListRelation);
    private:
        Event source;
        Event target;
        std::vector<std::string> listRelation;
        std::string test="";

};
class Marking{
    private:
        std::vector<Event> Exclude;
        std::vector<Event> Include;
        std::vector<Event> Response;
    public:
        Marking(){};
        explicit Marking(std::vector<Event> _exclude, std::vector<Event> _include, std::vector<Event> _response):
                Exclude(_exclude), Include(_include), Response(_response) {}
        std::vector<Event> getExclude();
        std::vector<Event> getInclude();
        std::vector<Event> getResponse();
        void setExclude(std::vector<Event> exclude);
        void setInclude(std::vector<Event> include);
        void setResponse(std::vector<Event> response);
};

class DCRClass{
    public:
        DCRClass();
        explicit DCRClass(std::vector<Event> _listEvent, Marking _initMarking, std::vector<ERE> _listERE):
                listEvent(_listEvent), initMarking(_initMarking), listERE(_listERE) {}
        void setEvent(std::vector<Event> ListEvent);
        void setMarking(Marking InitMarking);
        void setERE(std::vector<ERE> ListERE);
        std::vector<Event> getListEvent();
        Marking getMarking();
        std::vector<ERE> getERE();
        std::string description();
    private:
        std::vector<Event> listEvent;
        Marking initMarking;
        std::vector<ERE> listERE;
        
};
}

#endif
