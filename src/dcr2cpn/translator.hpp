#ifndef DCR2CPN_TRANSLATOR_H_
#define DCR2CPN_TRANSLATOR_H_

#include "DCR.hpp"
#include "../../../include/Helena.hpp"
#include <string>

namespace DCR2CPN {


bool isSubOf2(const std::string& ParentNameInput, const std::string& EventNameInput, std::vector<DCR2CPN::Event> listEvent);
/** 
 *  This function use to load dcr xml file and put it into dcr class  
 */
DCRClass readDCRFromXML(const std::string& DCR_XML_FILE);


/** @class Subnet.
 * 
 *  SubNet class use to handle all information needed in creating a transition, which is corresponding to an event in dcr graph
 */
class SubNet {
    public:
        /** Constructor. Initializes id and name of transition */
        SubNet(const std::string& _name, const std::string& _id): name(_name), id(_id) {}
        
        std::string get_name();
        std::string get_id();

        /** Use to add execute params represent execute action  */
        void add_executecvparams(const std::string& param);
        /** Use to add include params represent include relation  */
        void add_includecvparams(const std::string& param);
        /** Use to add response params represent response action  */
        void add_responsecvparams(const std::string& param);

        /** Use to add milestone condition relation  */
        void add_cmilestone(const std::string& param);
        /** Use to add condition relation  */
        void add_ccondition(const std::string& param);
        
        /** Create transition based on added relations  */
        HELENA::TransitionNodePtr createTransition();

    private:
        std::string name;
        std::string id;

        std::vector<std::string> executeCVParams;
        std::vector<std::string> includeCVParams;
        std::vector<std::string> responseCVParams;

        std::vector<std::string> cMilestone;
        std::vector<std::string> cCondition;
};
typedef std::shared_ptr<SubNet> SubNetPtr;


/** @class Translator
 * 
 * Translator class use to handle all information needed in translating a dcr class obj into helena code.
 */ 
class Dcr2CpnTranslator {
    public:
        /** Constructor. Initializes dcrClass */
        Dcr2CpnTranslator(DCRClass _dcrClass): dcrClass(_dcrClass) {}

        /** add new subnet class obj into list */
        void add_subnet(const std::string& subnet_name, SubNetPtr _subnet);
        /** get subnet class obj by name */
        SubNetPtr get_subnet_by_name(const std::string& subnet_name);
        /** get subnet class obj by id */
        std::string get_subnet_id(const std::string& subnet_name );

        /** translate a dcr class obj into helena code */
        HELENA::StructuredNetNodePtr translate();

        /** generate static code for colours definitions (.lna file) */
        void generateInitColours();
        /** generate static code for places definitions (.lna file) */
        void generateInitPlaces();
        /** generate static code for functions definitions (.lna file) */
        void generateInitFunctions();

    private:
        DCRClass dcrClass;
        HELENA::StructuredNetNodePtr net;
        std::map<std::string, SubNetPtr> subnets;
};

}

#endif