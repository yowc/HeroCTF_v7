#pragma once
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include <llvm/ADT/APInt.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/Support/Casting.h>

#include <string>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>

using namespace llvm;

inline Loop* findFirstLoop(LoopInfo &LI) {
  Loop* found_loop = nullptr;
  for(Loop *L : LI) {
    found_loop = L;
  } // first top-level loop
  return found_loop;
}

inline Loop* findLastLoop(LoopInfo &LI) {
  Loop* found_loop = nullptr;
  for(Loop *L : LI) {
    found_loop = L;
    break;
  } // first top-level loop
  return found_loop;
}

// Check loop executes exactly N iterations (via loop header parsing).
inline bool loop_upper_bound_check(Loop *L, uint64_t bound) {
   if (!L) return false;

  BasicBlock *loop_header = L->getHeader();
  if(loop_header->size() < 2) return false;
  auto It = loop_header->begin();
  if(It == loop_header->end()) return false;
  ++It; // Move to 2nd instruction
  if (It == loop_header->end()) return false;
  Instruction *cmp = &*It;
  ICmpInst *icmp_inst = dyn_cast<ICmpInst>(cmp);
  if(!icmp_inst) return false;
  Value *upper_bound = icmp_inst->getOperand(1);
  if(ConstantInt *const_upper_bound = dyn_cast<ConstantInt>(upper_bound)) {
    return const_upper_bound->getZExtValue() == bound; // upper bound constant
  }
  return false;
}

inline bool loop_lower_bound_check(Loop* L, uint64_t bound) {
  if(!L) return false;

  BasicBlock *loop_preheader = L->getLoopPreheader();
  if(!loop_preheader) return false;
  if(loop_preheader->size() < 2) return false;
  auto It = loop_preheader->begin();
  Instruction *store = &*It;
  if(!store) return false;
  StoreInst *store_inst = dyn_cast<StoreInst>(store);
  if(!store_inst) return false;
  Value *lower_bound = store_inst->getOperand(0);
  if(!lower_bound) return false;
  if(ConstantInt *const_lower_bound = dyn_cast<ConstantInt>(lower_bound)) {
    return const_lower_bound->getZExtValue() == bound; // upper bound constant
  }
  return false;
  
}

static GlobalVariable *find_global_where_value_is_stored(Value *value) {
  if(!value) return nullptr;

  SmallVector<Value *, 128> work_list;
  work_list.push_back(value);

  while(!work_list.empty()) {
    Value *cur = work_list.pop_back_val();

    for(User *user : cur->users()) {
      if(StoreInst *store_inst = dyn_cast<StoreInst>(user)) {
          return dyn_cast<GlobalVariable>(store_inst->getPointerOperand());
      }
      if(Instruction *cur_inst = dyn_cast<Instruction>(user)) {
        switch (cur_inst->getOpcode()) {
        case Instruction::BitCast:
        case Instruction::AddrSpaceCast:
        case Instruction::GetElementPtr:
        case Instruction::IntToPtr:
        case Instruction::PtrToInt:
        case Instruction::Trunc:
        case Instruction::ZExt:
        case Instruction::SExt:
        case Instruction::PHI:
        case Instruction::Select:
        case Instruction::Load:
        case Instruction::InsertValue:
        case Instruction::ExtractValue:
          work_list.push_back(cur_inst);
          break;
        default:
          work_list.push_back(cur_inst);
          break;
        }
        continue;
      }

      if(ConstantExpr *constant_expr_user = dyn_cast<ConstantExpr>(user)) {
        work_list.push_back(constant_expr_user);
        continue;
      }

      if(Value *value_user = dyn_cast<Value>(user)) {
        work_list.push_back(value_user);
      }
    }
  }

  return nullptr;
}

static GetElementPtrInst *find_gep_in_same_block(Value *start_value) {
  if(!start_value) return nullptr;

  Instruction *cur_inst = dyn_cast<Instruction>(start_value);
  if(!cur_inst) return nullptr;

  BasicBlock *basic_block = cur_inst->getParent();
  Value *cur_value = start_value;
  Value *next_value = nullptr;

  for(auto basic_block_iterator = BasicBlock::iterator(cur_inst); basic_block_iterator != basic_block->begin();) {
    Instruction *next_inst = &*basic_block_iterator--;

    if(GetElementPtrInst *get_element_ptr_inst = dyn_cast<GetElementPtrInst>(next_inst))
      return get_element_ptr_inst;

    if(CastInst *cast_inst = dyn_cast<CastInst>(next_inst)) {
      next_value = cast_inst->getOperand(0);
      continue;
    }

    if(LoadInst *load_inst = dyn_cast<LoadInst>(next_inst)) {
      next_value = load_inst->getPointerOperand();
      continue;
    }

    if(StoreInst *store_inst = dyn_cast<StoreInst>(next_inst)) {
      next_value = store_inst->getOperand(0);
      continue;
    }

    if(SelectInst *sel_inst = dyn_cast<SelectInst>(next_inst)) {
      next_value = sel_inst->getTrueValue();
      continue;
    }

    if(next_value == cur_value) cur_value = next_value;

    // Unknown instruction — stop.
    return nullptr;
  }

  return nullptr;
}

static void remove_impossible_if_block(BasicBlock *then_basic_block, BasicBlock *cont_basic_block) {
  SmallVector<BasicBlock*, 8> Preds(predecessors(then_basic_block));
  for(BasicBlock *cur_pred : Preds) {
    Instruction *cur_term = cur_pred->getTerminator();
    for(unsigned i = 0; i < cur_term->getNumSuccessors(); ++i) {
      if(cur_term->getSuccessor(i) == then_basic_block) {
        cur_term->setSuccessor(i, cont_basic_block);
      }
    }
  }

  // erase instructions in then_basic_block
  while (!then_basic_block->empty()) {
    Instruction &cur_inst = then_basic_block->back();
    cur_inst.eraseFromParent();
  }

  // erase the block itself
  then_basic_block->eraseFromParent();
}

// leaking file name for chall_pass.cpp and driver_pipeline.cpp 
static void bailout_impl(Error err, const char *file, int line) {
  if(!err) return;
  std::string msg;
  handleAllErrors(std::move(err),
                  [&](ErrorInfoBase &EIB) { msg = EIB.message(); });
  errs() << "[-] " << msg << " -> " <<  file << ":" << line << "\n";
  exit(1);
}
#define BAILOUT(ERR) bailout_impl((ERR), __FILE__, __LINE__)

