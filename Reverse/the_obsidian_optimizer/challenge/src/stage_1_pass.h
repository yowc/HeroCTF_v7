#pragma once
#include "challenge_state.h"
#include "pass_utils.h"
#include "llvm/IR/PassManager.h"
#include <llvm/IR/Analysis.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/Support/Casting.h>

using namespace llvm;

struct stage1 : PassInfoMixin<stage1> {
  ChallengeState &state;
  std::string TargetCallee; // name of call inside the loop you expect (optional)

  stage1(ChallengeState &S, std::string Target="")
  : state(S), TargetCallee(std::move(Target)) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
    LoopAnalysis::Result &LI = FAM.getResult<LoopAnalysis>(F);
    Loop *L = findFirstLoop(LI);
    LLVMContext &ctx = F.getContext();
    CallInst *found_call = nullptr;
    Value *cmp = nullptr;
    Constant *const_41 = nullptr;
    BasicBlock *orig_bb = nullptr;
    Function *parent = nullptr;
    Module *module = nullptr;
    Type *i64_type = Type::getInt64Ty(ctx);;
    FunctionType *function_type = nullptr;
    Function *new_fn = nullptr;
    CallInst *new_found_call = nullptr;
    GlobalVariable *gfp_1 = nullptr;
    std::vector<Value *> args;
    Value *is_41_val = nullptr;
    IRBuilder<> ir_builder(ctx);
    uint64_t val = 0;
    if(!L) return PreservedAnalyses::all();

    if(!loop_upper_bound_check(L, 42)) return PreservedAnalyses::all();

    // TODO make it more readable in desas
    for(BasicBlock *BB : L->blocks()) {
      for(Instruction &I : *BB) {
        if(CallInst *CI = dyn_cast<CallInst>(&I)) {
          if(Function *Callee = CI->getCalledFunction()) {
            if(Callee->getName() == TargetCallee) {
              found_call = CI;
              BasicBlock *Pred = BB->getSinglePredecessor();
              if(!Pred) continue;
              if(BranchInst *Br = dyn_cast<BranchInst>(Pred->getTerminator())) {
                if(!Br->isConditional()) continue;
                if(ICmpInst *Cmp = dyn_cast<ICmpInst>(Br->getCondition())) {
                  if(Cmp->getCmpPredicate() == ICmpInst::Predicate::ICMP_EQ) {
                    ConstantInt *test = dyn_cast<ConstantInt>(Cmp->getOperand(1));
                    APInt C = test->getValue();
                    val = C.getZExtValue();
                    cmp = Cmp; 
                    break;
                  }
                }
              }
            }
          }
        }
      }
      if(found_call) break;
    }
    if(!found_call) goto failed;
    if(!cmp) goto failed;
    if(val != 41) goto failed;

    ir_builder.SetInsertPoint(found_call);
    const_41 = ConstantInt::get(cmp->getType(), 41);
    is_41_val = ir_builder.CreateICmpEQ(cmp, const_41);
    if(!is_41_val) goto failed;


    orig_bb = found_call->getParent();
    parent = orig_bb->getParent();
    module = parent->getParent();

    function_type = FunctionType::get(i64_type, {i64_type,i64_type,i64_type,i64_type}, false);

    args = std::vector<Value *>(found_call->arg_begin(), found_call->arg_end());
    new_fn = Function::Create(function_type, Function::ExternalLinkage, "secrets_stage0_factory", *module);
    new_found_call = ir_builder.CreateCall(new_fn, args);

    gfp_1 = find_global_where_value_is_stored(found_call);
    // Replace all uses of the old call
    if(!found_call->use_empty())
        found_call->replaceAllUsesWith(new_found_call);

    // Remove the old one
    found_call->eraseFromParent();

    if(gfp_1) {
      errs() << "[Stage1] succeeded\n";
      state.stage1 = true;
      state.gv_stage1 = gfp_1->getName().str();
      return PreservedAnalyses::none();
    }

failed:
    return PreservedAnalyses::all();
  }
};
