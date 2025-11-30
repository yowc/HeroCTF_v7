#pragma once
#include "challenge_state.h"
#include "pass_utils.h"
#include "llvm/IR/PassManager.h"
#include <llvm/ADT/APInt.h>
#include <llvm/IR/Analysis.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Casting.h>

struct stage5 : llvm::PassInfoMixin<stage5> {
  ChallengeState &state;
  stage5(ChallengeState &S) : state(S) {}

  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM) {
    if(!state.stage4 || state.gv_rv.empty() || state.gv_table_size.empty() || state.gv_table.empty()) return llvm::PreservedAnalyses::all();
    bool valid_header = false, valid_if = false, valid_call = false;
    auto &LI = FAM.getResult<LoopAnalysis>(F);
    uint64_t lower_bound = 0x0;
    Value *gv_tbs = nullptr;
    Value *gv_tb = nullptr;
    Value *gv_rv = nullptr;
    GetElementPtrInst *gep_inst = nullptr;
    BasicBlock *loop_preheader = nullptr;
    BasicBlock::iterator loop_preheader_it;
    Instruction *store = nullptr;
    StoreInst *store_inst = nullptr;
    Value *loop_index = nullptr;
    BasicBlock *loop_header = nullptr;
    BasicBlock::iterator loop_header_it;
    Instruction *loop_header_load_idx = nullptr;
    Instruction *load_g_tbs = nullptr;
    Instruction *add = nullptr;
    Instruction *loop_header_icmp = nullptr;
    BasicBlock *loop_if_block = nullptr;
    BasicBlock::iterator loop_if_block_it;
    Instruction *loop_if_load_idx = nullptr;
    Instruction *loop_if_icmp = nullptr;
    ConstantInt *loop_if_icmp_const = nullptr;
    APInt loop_if_icmp_const_value;
    CallInst *call_inst = nullptr;
    BasicBlock *loop_call_block = nullptr;
    Value *func_ptr = nullptr;
    LoadInst *load_from_g_tb = nullptr;
    LoadInst *loop_call_load_idx = nullptr;
    LoadInst *arg_0 = nullptr;
    Loop *loop = findLastLoop(LI);

    if(!loop) goto failed;


    if(!loop_lower_bound_check(loop, lower_bound)) {
      errs() << "[!] Carefull to optimization the loop preheader could be merge with previous block so add any check to global variables could help\n";
      goto failed;
    } 
    loop_preheader = loop->getLoopPreheader();
    loop_preheader_it = loop_preheader->begin();
    store = &*loop_preheader_it;
    store_inst = dyn_cast<StoreInst>(store);
    loop_index = store_inst->getOperand(1);
    for(BasicBlock *BB : loop->blocks()) {
      for(Instruction &I : *BB) {
        if(LoadInst *LI = dyn_cast<LoadInst>(&I)) {
          if(GlobalVariable *GV = dyn_cast<GlobalVariable>(LI->getPointerOperand())) {
            if(GV->getName() == state.gv_table_size) {
              gv_tbs = GV;
            } else if(GV->getName() == state.gv_table) {
              gv_tb = GV;
            } else if(GV->getName() == state.gv_rv) {
              gv_rv = GV;
            }
          }
        }
      }
    }
    if(!gv_tbs || !gv_tb || !gv_rv) goto failed;
    // g_tbs is add one in loop header and check with ult of loop index
    loop_header = loop->getHeader();
    if(loop_header->size() < 5) goto failed; 
    loop_header_it = loop_header->begin();
    loop_header_load_idx = &*loop_header_it;
    load_g_tbs = loop_header_load_idx->getNextNode();
    add = load_g_tbs->getNextNode();
    loop_header_icmp = add->getNextNode();
    if(loop_header_load_idx->getOperand(0) != loop_index) {
      goto failed;
    }
    if(load_g_tbs->getOperand(0) != gv_tbs) goto failed;

    if(add->getOperand(0) != load_g_tbs) goto failed;
    if(loop_header_icmp->getOperand(0) != loop_header_load_idx || loop_header_icmp->getOperand(1) != add) goto failed;

    valid_header = true;
    // check the condition for loop index == 3
    loop_if_block = loop_header->getNextNode();
    if(loop_if_block->size() < 3) goto failed;
    loop_if_block_it = loop_if_block->begin();
    loop_if_load_idx = &*loop_if_block_it;
    loop_if_icmp = loop_if_load_idx->getNextNode();

    if(loop_if_load_idx->getOperand(0) != loop_index) goto failed;

    loop_if_icmp_const = dyn_cast<ConstantInt>(loop_if_icmp->getOperand(1));
    loop_if_icmp_const_value = loop_if_icmp_const->getValue();
    if(loop_if_icmp->getOperand(0) != loop_if_load_idx || loop_if_icmp_const_value != 3) goto failed;

    valid_if = true;

    // check for extraction of g_tb with loop index
    loop_call_block = loop_if_block->getNextNode();
    // check from call go up until we found a getelementptr
    // check for g_rv
    // check load ptr %7
    for(Instruction &I: *loop_call_block) {
      if((call_inst = dyn_cast<CallInst>(&I))) {
        func_ptr = call_inst->getCalledOperand();
        func_ptr = func_ptr->stripPointerCasts();
        gep_inst = find_gep_in_same_block(func_ptr);
        if(gep_inst == nullptr) goto failed;
        load_from_g_tb = dyn_cast<LoadInst>(gep_inst->getOperand(0));
        loop_call_load_idx = dyn_cast<LoadInst>(gep_inst->getOperand(1));
        if(!load_from_g_tb || !loop_call_load_idx) goto failed; 
        if(load_from_g_tb->getPointerOperand() != gv_tb) goto failed;
        if(loop_call_load_idx->getPointerOperand() != loop_index) goto failed;
        if(call_inst->arg_empty()) goto failed;
        arg_0 = dyn_cast<LoadInst>(call_inst->getArgOperand(0));
        if(!arg_0) goto failed;
        if(arg_0->getPointerOperand() != gv_rv) goto failed;
        valid_call = true;
      }
    }
    
    if(valid_header && valid_if && valid_call) {
      state.stage5 = true;
      errs() << "[Stage5] succeeded \n";
    }

failed:
    return llvm::PreservedAnalyses::all();
  }
};
