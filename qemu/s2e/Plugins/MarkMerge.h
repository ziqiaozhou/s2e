#ifndef MARKMERGEINSTRUCTIONS_H

#define MARKMERGEINSTRUCTIONS_H
#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include "BaseInstructionsOb.h"
namespace s2e {
namespace plugins {

class MarkMerge: public Plugin, public BaseInstructionsObPluginInvokerInterface {
	 S2E_PLUGIN
	public:
		    MarkMerge(S2E *s2e): Plugin(s2e) {}
			void initialize();
			void handleOpcodeInvocation(S2EExecutionState * ,uint64_t data,uint64_t size);
};

} // namespace plugins
} // namespace s2e

#endif
