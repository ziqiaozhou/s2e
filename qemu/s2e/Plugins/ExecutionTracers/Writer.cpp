/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include <iomanip>
#include <cctype>

#include <s2e/S2E.h>
#include "klee/Internal/Module/InstructionInfoTable.h"
#include <s2e/Utils.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include "Writer.h"
#include "ExecutionTracer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Type.h"
#include "llvm/Constants.h"
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
#include "llvm/IR/Function.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/TypeBuilder.h"
#else
#include "llvm/Attributes.h"
#include "llvm/BasicBlock.h"
#include "llvm/Constants.h"
#include "llvm/Function.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#if LLVM_VERSION_CODE <= LLVM_VERSION(3, 1)
#include "llvm/Target/TargetData.h"
#else
#include "llvm/DataLayout.h"
#include "llvm/TypeBuilder.h"
#endif
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <fstream>
#include <sstream>
using namespace llvm;
using namespace klee;
namespace s2e {
	namespace plugins {

		S2E_DEFINE_PLUGIN(Writer, " Writer plugin", "Writer", "ExecutionTracer");

		Writer::Writer(S2E* s2e)
			: Plugin(s2e)
		{
			m_testIndex = 0;
			m_pathsExplored = 0;
			WritePC=false;
			WriteSymPath=false;
			symPathWriter=0;
			OnlyOutputStatesCoveringNew=false;
		}

		void Writer::initialize()
		{
			ConfigFile *cfg = s2e()->getConfig();

			WritePC = cfg->getInt(getConfigKey() + ".write_pcs")>0?true:false;
			WriteSymPath=cfg->getBool(getConfigKey() + ".write_sym_paths");
OnlyOutputStatesCoveringNew=cfg->getBool(getConfigKey() + ".onlynew");
			if(WriteSymPath){
				symPathWriter = new klee::TreeStreamWriter(s2e()->getOutputFilename("symPaths.ts"));
				s2e()->getExecutor()->setSymbolicPathWriter(symPathWriter);
				s2e()->getCorePlugin()->onStateFork.connect(
							sigc::mem_fun(*this, &Writer::stateFork));

			}
			s2e()->getCorePlugin()->onStateKill.connect(
						sigc::mem_fun(*this, &Writer::stateTerminate));

		}
		std::string Writer::GotoLine(std::fstream& file, unsigned int num){
			std::string line;
			for(int nline=0;nline<num;nline++){
				getline(file,line);
			}
			return line;
		}
		const InstructionInfo &Writer::getLastNonKleeInternalInstruction(KModule *kmodule,const ExecutionState &state,
					Instruction ** lastInstruction) {
			// unroll the stack of the applications state and find
			//   // the last instruction which is not inside a KLEE internal function
			ExecutionState::stack_ty::const_reverse_iterator it = state.stack.rbegin(),
			itE = state.stack.rend();
			//
			//// don't check beyond the outermost function (i.e. main())
			itE--;
			//
			const InstructionInfo * ii = 0;
			if (kmodule->internalFunctions.count(it->kf->function) == 0){
				ii =  state.prevPC->info;
				*lastInstruction = state.prevPC->inst;
				//  Cannot return yet because even though
				//                                   //  it->function is not an internal function it might of
				//                                       //  been called from an internal function.
			}
			//                                           // Wind up the stack and check if we are in a KLEE internal function.
			//                                             // We visit the entire stack because we want to return a CallInstruction
			//                                               // that was not reached via any KLEE internal functions.
			for (;it != itE; ++it) {
				//                                                     // check calling instruction and if it is contained in a KLEE internal function
				const Function * f = (*it->caller).inst->getParent()->getParent();
				if (kmodule->internalFunctions.count(f)){
					ii=0;
					continue;
				}
				if (!ii){
					ii = (*it->caller).info;
					*lastInstruction = (*it->caller).inst;
				}
			}

			if (!ii) {
				//                                                                                                         // something went wrong, play safe and return the current instruction info
				*lastInstruction = state.prevPC->inst;
				return *state.prevPC->info;
			}
			return *ii;
		}
		std::string Writer::getCurrentLine(KModule* kmodule,ExecutionState * state){
			struct stat info;
			std::stringstream msg;
			Instruction * lastInst;
			const InstructionInfo &ii = getLastNonKleeInternalInstruction(kmodule,*state, &lastInst);
			if (ii.file != ""){
				std::string filename=ii.file;
				if(stat(filename.c_str(), &info )!=0){	
					std::fstream file(filename.c_str());
					std::string linestr=GotoLine(file,ii.line);
					if (filename.find("linux-3.18.37")>-1){
						msg<<"("<<linestr<<")\t"<<filename.substr(filename.find("linux-3.18.37")+strlen("linux-3.18.37"),filename.length())<<":"<<ii.line;
					}else{
						msg<<"("<<linestr<<")\t"<<filename<<":"<<ii.line;
					}
					file.close();
				}else{
					msg<<filename<<":"<<ii.line;
				}
			}
			else{
				msg<<"no file info";
			}
			return msg.str();
		}
		void Writer::stateFork(S2EExecutionState *state,
					const std::vector<S2EExecutionState*>& newStates,
					const std::vector<klee::ref<klee::Expr> >& newConditions){
			KModule* kmodule=s2e()->getExecutor()->getKModule();
			if(symPathWriter){
				S2EExecutionState* trueState=newStates[0],* falseState=newStates[1];//truestate==state
				std::string a="";
				falseState->symPathOS = symPathWriter->open(state->symPathOS);
				std::string line=getCurrentLine(kmodule,state);
				trueState->symPathOS<<"1"<<"->"<<line<<"\n";
				falseState->symPathOS<<"0"<<"->"<<line<<"\n";
			}
		}
		void Writer::stateTerminate(S2EExecutionState *state)
		{
			if(OnlyOutputStatesCoveringNew||state->coveredNew){
				ConcreteInputs out;
				bool success = s2e()->getExecutor()->getSymbolicSolution(*state, out);

#if 0
				foreach2(it, state.constraints.begin(), state.constraints.end()) {
					s2e()->getMessagesStream() << "Constraint: " << std::hex << *it << '\n';
				}
#endif
				S2EExecutor *executor=s2e()->getExecutor();
				if (!success) {
					s2e()->getWarningsStream() << "Could not get symbolic solutions" << '\n';
					return;
				}
				std::string obstr="";
				llvm::raw_string_ostream obstrs(obstr);

				for(unsigned i=0;i<state->observables.size();i++){
					obstrs<<"(Eq "<<state->observables[i].name<<" "<<state->observables[i].expr<<")\n";
				}

				if ( WritePC) {
					std::string constraints;
					std:: string declarestr="";
					llvm::raw_string_ostream declarestrs(declarestr);
					executor->getConstraintLog(*state, constraints,false);
					std::string a="";
					llvm::raw_string_ostream name(a);
					name<<state->getID()<<".pc";
					llvm::raw_ostream *f = s2e()->openOutputFile(name.str());
					for(std::vector<std::pair<const MemoryObject *, const Array *> >::iterator it= state->symbolics.begin();it!=state->symbolics.end();++it){
								declarestrs<<"array "<<it->second->name<<"["<<it->second->size<<"]: w32 -> w8 = symbolic\n";
					}
					*f << constraints;
					int assert_index=constraints.rfind("]");
					constraints.insert(assert_index,"\n"+obstrs.str());
					name<<"0";
					llvm::raw_ostream *f2 = s2e()->openOutputFile(name.str());
					*f2<<declarestrs.str()<<constraints;
					delete f2;
					f2=NULL;
					delete f;
				}
				if (symPathWriter) {
					std::vector<unsigned char> symbolicBranches;
					symPathWriter->readStream(executor->getSymbolicPathStreamID(*state),
								symbolicBranches);
					std::string a="";
					llvm::raw_string_ostream name(a);
					name<<state->getID()<<".sym.path";
					llvm::raw_ostream *f = s2e()->openOutputFile(name.str());
					for (std::vector<unsigned char>::iterator I = symbolicBranches.begin(), E = symbolicBranches.end(); I!=E; ++I) {
						*f << *I ;
					}
					delete f;
				}
				s2e()->getMessagesStream() << '\n';
			}
		}
	}
}
