#pragma once
#include "challenge_state.h"
#include "pass_utils.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/Instructions.h"
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/Support/Casting.h>
#include <string>

using namespace llvm;

struct stage4 : public PassInfoMixin<stage4> {
  ChallengeState &state;
  stage4(ChallengeState &S) : state(S) {}

  PreservedAnalyses run(Function &F, [[maybe_unused]] FunctionAnalysisManager &FAM) {
    if (!state.stage3 || state.gv_stage3.empty()) return PreservedAnalyses::all();
    Module *M = F.getParent();

    GlobalVariable *rv = nullptr;
    GlobalVariable *tb = nullptr;
    GlobalVariable *tbs = nullptr;
    GlobalVariable *gv_3 = nullptr;
    GlobalVariable *GV = nullptr;
    int found_global_variables = 0;
    Value *next_node = nullptr;

    for (GlobalVariable &global_var : M->globals()) {
        if(global_var.getName() == state.gv_stage3) {
          gv_3 = &global_var;
        }
    }

    if(!gv_3) goto failed;

    for(User *U: gv_3->users()) {
      if (LoadInst *LI = dyn_cast<LoadInst>(U)) {
        next_node = LI->getNextNode();
        if(dyn_cast<CallInst>(next_node)) {
          GV = find_global_where_value_is_stored(next_node);
          if(GV != nullptr) {
            if(!found_global_variables) {
              // Force the player to read and store random value first
              tb = GV;
            } else if(found_global_variables == 1) {
              tbs = GV;
            } else {
              rv = GV;
            }
            found_global_variables++;
          }
        }
      }
    }

    if(found_global_variables == 3) {
      state.gv_rv = rv->getName();
      state.gv_table_size = tbs->getName();
      state.gv_table = tb->getName();
      state.stage4 = true;
      errs() << "[Stage4] succeeded \n";
      return PreservedAnalyses::none();
    }

failed:
    return PreservedAnalyses::all();
  }
};

