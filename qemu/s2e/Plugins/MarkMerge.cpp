#include "MarkMerge.h"
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Opcodes.h>

#include <iostream>
#include <sstream>
namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MarkMerge, "Mark merge check plugin", "",);

void MarkMerge::initialize(){
}
void MarkMerge::handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t address,
                                        uint64_t size) {
    
    std::string nameStr = "unnamed";
   
    s2e()->getMessagesStream(state)
            << "Inserting merge mark data at " << hexval(address)
            << " of size " << (size)
            << " with name '" << nameStr << "'\n";
    std::vector<unsigned char> concreteData;
	std::vector<klee::ref<klee::Expr> > symb;
	klee::ObjectPair op = state->addressSpace.findObject(address & S2E_RAM_OBJECT_MASK);
	state->addMergeOb(nameStr,op.first);
}
}
}
