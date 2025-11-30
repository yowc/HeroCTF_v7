#pragma once
#include "challenge_state.h"
#include "pass_utils.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/Instructions.h"
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/Support/Casting.h>
#include <string>

using namespace llvm;

struct stage3 : public PassInfoMixin<stage3> {
  ChallengeState &state;
  stage3(ChallengeState &S) : state(S) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
    if(!state.stage2 || state.gv_stage2.empty()) return PreservedAnalyses::all();

    auto &LI = FAM.getResult<LoopAnalysis>(F);
    LLVMContext &ctx = F.getContext();
    Type *i32_type = Type::getInt32Ty(ctx);
    bool changed = false, changed_0 = false, changed_1 = false;
    uint64_t lower_bound = 0xffffffffULL;
    uint64_t upper_bound = 0x1ffffffffULL;
    BasicBlock *loop_preheader = nullptr;
    BasicBlock::iterator loop_preheader_iterator;
    Instruction *store = nullptr;
    StoreInst *store_inst = nullptr;
    Value *loop_index = nullptr;
    GlobalVariable *gfp_3 = nullptr;
    Instruction *gfp_3_load = nullptr;
    Value *trunc = nullptr;
    Value *sext = nullptr;
    Constant *new_const = nullptr;
    Value *next_node = nullptr;
    Value *op1 = nullptr;

    for (Loop *loop : LI) {
      if(!loop_upper_bound_check(loop, upper_bound)) continue;
      if(!loop_lower_bound_check(loop, lower_bound)) continue;

      loop_preheader = loop->getLoopPreheader();
      loop_preheader_iterator = loop_preheader->begin();
      store = &*loop_preheader_iterator;
      store_inst = dyn_cast<StoreInst>(store);
      loop_index = store_inst->getOperand(1);

      for (BasicBlock *basic_blocks : loop->blocks()) {
        for (Instruction &cur_inst : *basic_blocks) {
          if (LoadInst *load_inst = dyn_cast<LoadInst>(&cur_inst)) {
            if (GlobalVariable *global_var = dyn_cast<GlobalVariable>(load_inst->getPointerOperand())) {
              if (global_var->getName() == state.gv_stage2) {
                gfp_3_load = &cur_inst;
                break;
              }
            }
          }
        }
        if (gfp_3_load) break;
      }
    }
    if(!loop_index) goto failed;

    for (User *U : loop_index->users()) {
      if (auto *LI = dyn_cast<LoadInst>(U)) {
        next_node = LI->getNextNode();
        if(auto *CI = dyn_cast<ICmpInst>(next_node)) {
          op1 = CI->getOperand(1);
          if(auto *const_value = dyn_cast<ConstantInt>(op1)) {
            if(const_value->getZExtValue() == 0xfeedfacf) {
              IRBuilder<> b_sign(CI);
              trunc = b_sign.CreateTrunc(LI, i32_type, "custom_0");
              CI->setOperand(0, trunc);
              changed_0 = true;
            }
            if(const_value->getSExtValue() == -1) {
              IRBuilder<> b_sign(CI);
              trunc = b_sign.CreateTrunc(LI, i32_type, "custom_1");
              sext = b_sign.CreateSExt(trunc, i32_type, "custom_2");
              new_const = ConstantInt::get(i32_type, -1, true);
              CI->setOperand(0, sext);
              CI->setOperand(1, new_const);
              changed_1 = true;
            }
          }            
        }
      }
    }

    changed = changed_0 && changed_1;
    if(changed) {
      gfp_3 = find_global_where_value_is_stored(gfp_3_load);
      if(gfp_3) {

        state.stage3 = true;
        state.gv_stage3 = gfp_3->getName().str();
        errs() << "[Stage3] succeeded \n";
        return PreservedAnalyses::none();
      }
    }
failed:
    return PreservedAnalyses::all();
  }
};
