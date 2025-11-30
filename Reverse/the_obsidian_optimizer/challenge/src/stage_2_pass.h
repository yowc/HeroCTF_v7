#pragma once
#include "challenge_state.h"
#include "pass_utils.h"
#include "llvm/IR/PassManager.h"
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/Analysis.h>
#include <llvm/IR/Constants.h>
#include <string>

using namespace llvm;

struct stage2 : public PassInfoMixin<stage2> {
  ChallengeState &state;
  stage2(ChallengeState &S) : state(S) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
    if(!state.stage1 || state.gv_stage1.empty()) {
      return PreservedAnalyses::all();
    }

    uint64_t trip_count = 0x1337ULL;
    LoopAnalysis::Result &LI = FAM.getResult<LoopAnalysis>(F);
    // ScalarEvolutionAnalysis::Result &SE = FAM.getResult<ScalarEvolutionAnalysis>(F);
    Loop *loop = nullptr;
    LoadInst *load_global = nullptr;
    BasicBlock *loop_preheader = nullptr;
    BasicBlock::iterator loop_preheader_iterator;
    Instruction *store = nullptr;
    StoreInst *store_inst = nullptr;
    Value *loop_index = nullptr;
    Instruction *term = nullptr;
    Value *cond = nullptr;
    Value *other = nullptr;
    Value *after_supposed_loop_index = nullptr;
    User::use_iterator after_supposed_loop_index_use_iterator;
    Use *supposed_load = nullptr;
    LoadInst *load_loop_index_inst = nullptr;
    bool impossible = false;
    APInt neg1;
    GlobalVariable *gfp_2 = nullptr;
    CallInst *global_call = nullptr;
    for(Loop *L : LI) {
      // require exact trip count 0x1337
      if(!loop_upper_bound_check(L, trip_count)) continue;
      // it means max born for i is 0x1336
      // but we will check something like i == -1
      if(!loop_lower_bound_check(L, 0)) continue;

      loop = L;
    }
    if(!loop) goto failed;

    loop_preheader = loop->getLoopPreheader();
    if(loop_preheader->size() < 2) goto failed;
    loop_preheader_iterator = loop_preheader->begin();
    store = &*loop_preheader_iterator;
    store_inst = dyn_cast<StoreInst>(store);
    loop_index = store_inst->getOperand(1);

    for(BasicBlock *BB : loop->blocks()) {
      // look for loads from the stage1 global in this block
      for(Instruction &I : *BB) {
        if(LoadInst *LIi = dyn_cast<LoadInst>(&I)) {
          if(GlobalVariable *GV = dyn_cast<GlobalVariable>(LIi->getPointerOperand())) {
            if(GV->getName() != state.gv_stage1) continue;
            load_global = LIi;
          }
        }
      }
    }
    // found a load from gv_stage1; now search for a conditional branch that check i
    // Search the whole loop for a conditional branch using an icmp with i
    for(BasicBlock *BB2 : loop->blocks()) {
      term = BB2->getTerminator();
      if(!term) continue;
      if(BranchInst *Br = dyn_cast<BranchInst>(term)) {
        if(!Br->isConditional()) continue;
        cond = Br->getCondition();
        // Go up on Cond check if the compared value is from i need to define i
        if(ICmpInst *IC = dyn_cast<ICmpInst>(cond)) {
          other = IC->getOperand(1);
          after_supposed_loop_index = IC->getOperand(0);
          // It should be loaded before use if it's our i
          after_supposed_loop_index_use_iterator = after_supposed_loop_index->use_begin();
          supposed_load = &*after_supposed_loop_index_use_iterator;

          load_loop_index_inst = dyn_cast<LoadInst>(supposed_load->get());
          if(!load_loop_index_inst) continue;

          // If the following if failed it means it's not our loop index
          if(load_loop_index_inst->getOperand(0) != loop_index) continue;
          
          // Only handle integer constant compares
          if(!isa<ConstantInt>(other)) continue;
          const APInt &C = cast<ConstantInt>(other)->getValue();

          if(IC->getPredicate() == ICmpInst::ICMP_EQ) {
            // detect -1 for the bitwidth
            APInt neg1 = APInt(C.getBitWidth(), -1, true);
            if(C == neg1) impossible = true;
          }

          if(!impossible) continue;
          gfp_2 = find_global_where_value_is_stored(load_global);
          global_call = NULL;
          for (User *U : load_global->users()) {
            if((global_call = dyn_cast<CallInst>(U))) {
              break;
            }
          }

          if(!global_call) continue;

          remove_impossible_if_block(BB2, Br->getSuccessor(0));
          if(gfp_2) {
            state.stage2 = true;
            state.gv_stage2 = gfp_2->getName().str();
            errs() << "[Stage2] succeeded\n";
            return PreservedAnalyses::none(); 
        }
      }
    }
  }

failed:
  return PreservedAnalyses::all();
  }
};
