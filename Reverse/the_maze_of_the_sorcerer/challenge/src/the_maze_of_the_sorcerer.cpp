#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include <cstring>
#include <llvm/IR/Analysis.h>
#include <llvm/IR/CmpPredicate.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/Compiler.h>
#include <llvm/IR/BasicBlock.h>
#include <fstream>
#include <llvm/Transforms/Utils/LoopUtils.h>
#include <sstream>
#include <vector>
#include <map>

using namespace llvm;

namespace hero {
  // TODO move this to chall_pass.hpp
  typedef enum ENTITY_S {
   HERO = 'H',
   EXIT = 'E',
   RUNE = 'R',
   ORCS = 'O'
  } ENTITY;

  bool opcodes_subset(const std::vector<Instruction*> &vec_a,
                   const std::vector<Instruction*> &vec_b) {
    std::map<unsigned, int> count_a, count_b;
    for(auto *I: vec_a) count_a[I->getOpcode()]++;
    for(auto *I: vec_b) count_b[I->getOpcode()]++;

    for(auto &p : count_a) {
        if (count_b[p.first] < p.second) {
            return false;
        }
    }
    return true;
  }

  bool opcodes_equivalent(const std::vector<Instruction*> &a,
                       const std::vector<Instruction*> &b) {
    return opcodes_subset(a, b) && opcodes_subset(b, a);
  }

  // check icmp
  bool check_inst_0(std::vector<Instruction *> &insts, ICmpInst::Predicate v_pred) {
    for(auto *I: insts) {
      if(auto *icmp = dyn_cast<ICmpInst>(I)) {
        ICmpInst::Predicate pred = icmp->getPredicate();
        if(pred == v_pred) {
          return true;
        }
      }
    }
    return false;
  }

  bool check_inst_1(std::vector<Instruction *> &insts, signed add_value) {
    for(auto *I: insts) {
      Value *op = I->getOperand(1);
      if(Constant *cur_const = dyn_cast<Constant>(op)) {
          signed entity = cur_const->getUniqueInteger().getSExtValue(); 
          if(entity == add_value) {
            return true;
          }
        }
    }
    return false;
  }

  bool check_inst_2(std::vector<Instruction *> &insts, signed store_value) {
    for(auto *I: insts) {
      Value *op = I->getOperand(0);
      if(Constant *cur_const = dyn_cast<Constant>(op)) {
          signed entity = cur_const->getUniqueInteger().getSExtValue(); 
          if(entity == store_value) {
            return true;
          }
        }
    }
    return false;
  }

  bool check_inst_3(std::vector<Instruction *> &insts) {
    for(auto *I: insts) {
      if(auto *gep = dyn_cast<GetElementPtrInst>(I)) {
        Value *op = gep->getPointerOperand();
        if(auto *gv = dyn_cast<GlobalVariable>(op)) {
          if(gv->getName() == "g_map") {
            return true;
          }
        }      
      }
    }
    return false;
  }

  // TODO All of the function below exist in Instruction.h for easier reverse replace it ?  
  bool is_memory_instruction(Instruction *I) {
    if(I->getOpcode() >= Instruction::MemoryOpsBegin && I->getOpcode() < Instruction::MemoryOpsEnd) {
      return true;
    }
    return false;
  } 

  bool is_term_instruction(Instruction *I) {
    if(I->getOpcode() >= Instruction::TermOpsBegin && I->getOpcode() < Instruction::TermOpsEnd) {
      return true;
    }
    return false;
  } 

  bool is_other_instruction(Instruction *I) {
    if(I->getOpcode() >= Instruction::OtherOpsBegin && I->getOpcode() < Instruction::OtherOpsEnd) {
      return true;
    }
    return false;
  } 

  class CustomFunction {
    // BasicBlock *original;
    std::vector<BasicBlock*> basic_blocks;

  public:
    CustomFunction(Function &F) {
      for(BasicBlock &BB: F) {
        basic_blocks.push_back(&BB);
      }
    }

      BasicBlock* get_block_at(size_t index) {
        if(index < basic_blocks.size()) {
          return basic_blocks[index];
        }
        return nullptr;
      }

      size_t size() const {
        return basic_blocks.size();
      }


    bool filter_instructions_in_block(
        size_t index,
        std::vector<Instruction*> &valid_inst,
        std::function<bool(Instruction*)> predicate,
        bool keep_matches = true
    ) {
        if(index >= size())
            return false;

        BasicBlock *basic_block = basic_blocks[index];

        if(valid_inst.empty()) {
            for (Instruction &instruction : *basic_block) {
              bool match = predicate(&instruction);
                if ((keep_matches && match) || ((!keep_matches) && !match)) {
                    valid_inst.push_back(&instruction);
                }
            }
        } else {
            valid_inst.erase(
                std::remove_if(valid_inst.begin(), valid_inst.end(),
                    [&](Instruction *inst) {
                      bool match = predicate(inst);
                      return keep_matches ? !match : match;
                    }),
                valid_inst.end()
            );
        }

        return !valid_inst.empty();
    }

    bool is_opcode_in_block(size_t index, unsigned opcode, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      auto is_same_opcode = [&](Instruction *I) { return I->getOpcode() == opcode; };
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return is_same_opcode(I);}, keep_matches);
    }

    bool is_block_fence_like(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return I->isFenceLike();}, keep_matches);
    }

    bool is_memory_instruction_in_block(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return is_memory_instruction(I);}, keep_matches);
    }

    bool is_term_instruction_in_block(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return is_term_instruction(I);}, keep_matches);
    }

    bool is_other_instruction_in_block(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return is_other_instruction(I);}, keep_matches);
    }

    bool is_commutative_instruction_in_block(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return I->isCommutative();}, keep_matches);
    }

    bool is_idempotent_instruction_in_block(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return I->isIdempotent();}, keep_matches);
    }

    bool is_nilpotent_instruction_in_block(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return I->isNilpotent();}, keep_matches);
    }

    bool is_associative_instruction_in_block(size_t index, std::vector<Instruction*> &valid_inst, bool keep_matches) {
      return filter_instructions_in_block(index, valid_inst, [&](Instruction *I) {return I->isAssociative();}, keep_matches);
    }

    bool is_block_subset_of(size_t index_a, size_t index_b) {
      std::vector<Instruction *> vec_a;
      std::vector<Instruction *> vec_b;

      if(index_a  > size() || index_b > size())
        return false;
      
      // TODO optimize this ?
      for(Instruction &I: *basic_blocks[index_a]) {
        vec_a.push_back(&I);
      }
      for(Instruction &I: *basic_blocks[index_b]) {
        vec_b.push_back(&I);
      }
      return opcodes_subset(vec_a, vec_b);
    }

    bool is_blocks_equivalent(size_t index_a, size_t index_b) {
      std::vector<Instruction *> vec_a;
      std::vector<Instruction *> vec_b;

      if(index_a  > size() || index_b > size())
        return false;

      // TODO optimize this ?
      for(Instruction &I: *basic_blocks[index_a]) {
        vec_a.push_back(&I);
      }
      for(Instruction &I: *basic_blocks[index_b]) {
        vec_b.push_back(&I);
      }
      return opcodes_equivalent(vec_a, vec_b);
    }

  };
  
  bool first_step(std::vector<CustomFunction> &custom_functions, std::vector<Instruction *> &get_direction_block_0_call) {
      unsigned all_units_set[4];
      std::vector<Instruction *> main_block_0_call;

      if(!custom_functions[2].is_other_instruction_in_block(0, main_block_0_call, true) || !custom_functions[2].is_block_fence_like(0, main_block_0_call, true) || !custom_functions[2].is_opcode_in_block(0, Instruction::Fence, main_block_0_call, false) || !custom_functions[2].is_opcode_in_block(0, Instruction::CatchPad, main_block_0_call, false)) {
        goto end;
      } 
      if(!custom_functions[1].is_block_fence_like(0, get_direction_block_0_call, true) || !custom_functions[1].is_opcode_in_block(0, Instruction::CatchRet, get_direction_block_0_call, false) || !custom_functions[1].is_opcode_in_block(0, Instruction::Invoke, get_direction_block_0_call, false)) {
        goto end;
      } 

      if(!opcodes_subset(get_direction_block_0_call, main_block_0_call)) {
        goto end;
      }

      for(auto test: main_block_0_call) {
        // shouldn't be anything else than call but we never know
        auto *func = dyn_cast<CallInst>(test);
        if(!func) {
          goto end;
        }
        Function *callee = func->getCalledFunction();
        if(!callee) {
          continue;
        }
        if("place_entity" != callee->getName()) {
          continue;
        }
        Value *op = test->getOperand(1);
        if(Constant *cur_const = dyn_cast<Constant>(op)) {
          unsigned entity = cur_const->getUniqueInteger().getZExtValue(); 
          switch(entity) {
            case HERO:
              all_units_set[0] += 1;
              break;
            case EXIT:
              all_units_set[1] += 1;
              break;
            case RUNE:
              all_units_set[2] += 1;
              break;
            case ORCS:
              all_units_set[3] += 1;
              break;
            default:
              break;
          }
        }
      }
      if(all_units_set[0] != all_units_set[1] != all_units_set[2] != all_units_set[3] != 1) {
        goto end;
      }
      return true;
end:
      return false;
  }

  bool second_step(std::vector<Instruction *> &get_direction_block_0_call) {
    unsigned chose_direction_calls = 0;
    for(auto test: get_direction_block_0_call) {
      auto *func = dyn_cast<CallInst>(test);
      if(!func) {
        goto end;
      }
      Function *callee = func->getCalledFunction();
      if(!callee) {
        continue;
      }
      if("chose_direction" != callee->getName()) {
        continue;
      }

      chose_direction_calls +=1;
    }

    if(chose_direction_calls != 2) {
      goto end;
    }
  return true;

end:
  return false;
  }

  bool third_step_4(std::vector<CustomFunction> &custom_functions, unsigned call_id, unsigned block_id,
                    Instruction *inst, ICmpInst::Predicate pred = ICmpInst::ICMP_UGT, signed value = 0) {
    std::vector<Instruction *> insts_garbage;
    bool result = false;

    if(!custom_functions[0].is_opcode_in_block(block_id, inst->getOpcode(), insts_garbage, true)) {
      goto end;
    }
    switch(call_id) {
      case 0:
        result = check_inst_0(insts_garbage, pred);
        break;
      case 1:
        result = check_inst_1(insts_garbage, value);
        break;
      case 2:
        result = check_inst_2(insts_garbage, value);
        break;
      case 3:
        result = check_inst_3(insts_garbage);
        break;
    }

  end:
    return result;
  }

  bool third_step_0(std::vector<CustomFunction> &custom_functions, std::vector<Instruction *> &block_1_mem_instruction, std::vector<Instruction *> &block_8_mem_instruction, std::vector<Instruction *> &block_11_mem_instruction) {
    bool result = false;
    if(!custom_functions[0].is_block_subset_of(1, 2)) {
      goto end;
    }
    // check compare on store and getElementPtr from other block 8 store and block 11 for getElementPtr
    if(!custom_functions[0].is_memory_instruction_in_block(1, block_1_mem_instruction, true) ||
        !custom_functions[0].is_opcode_in_block(1, Instruction::GetElementPtr, block_1_mem_instruction, false) ||
        !custom_functions[0].is_opcode_in_block(1, Instruction::Store, block_1_mem_instruction, false)) {
      goto end;
    }

    if(!custom_functions[0].is_memory_instruction_in_block(8, block_8_mem_instruction, true) ||
        !custom_functions[0].is_opcode_in_block(8, Instruction::Fence, block_8_mem_instruction, false) ||
        !custom_functions[0].is_opcode_in_block(8, Instruction::Alloca, block_8_mem_instruction, false) ||
        !custom_functions[0].is_opcode_in_block(8, Instruction::AtomicCmpXchg, block_8_mem_instruction, false)  ||
        !custom_functions[0].is_opcode_in_block(8, Instruction::AtomicRMW, block_8_mem_instruction, false) ||
        !custom_functions[0].is_opcode_in_block(8, Instruction::GetElementPtr, block_8_mem_instruction, false) ) {
      goto end;
    }

    if(!custom_functions[0].is_memory_instruction_in_block(11, block_11_mem_instruction, true) ||
        !custom_functions[0].is_opcode_in_block(11, Instruction::Fence, block_11_mem_instruction, false) ||
        !custom_functions[0].is_opcode_in_block(11, Instruction::Alloca, block_11_mem_instruction, false) ||
        !custom_functions[0].is_opcode_in_block(11, Instruction::AtomicCmpXchg, block_11_mem_instruction, false)  ||
        !custom_functions[0].is_opcode_in_block(11, Instruction::AtomicRMW, block_11_mem_instruction, false) ||
        !custom_functions[0].is_opcode_in_block(11, Instruction::Store, block_11_mem_instruction, false) ) {
      goto end;
    }

    if(!opcodes_subset(block_1_mem_instruction, block_8_mem_instruction)) {
      goto end;
    }

    if(!opcodes_subset(block_1_mem_instruction, block_11_mem_instruction)) {
      goto end;
    }

    if(block_1_mem_instruction.empty()) {
      goto end;
    }

    result = true;

end:
    return result;
  }

  bool third_step_1(std::vector<CustomFunction> &custom_functions, std::vector<Instruction *> &insts_garbage) {
    bool result = false;


    if(!custom_functions[0].is_block_subset_of(3, 2)) {
      goto end;
    }

    // Check for icmp in block 2 
    if(!custom_functions[0].is_other_instruction_in_block(2, insts_garbage, true) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::FCmp, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::PHI, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::Call, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::Select, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::UserOp1, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::UserOp2, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::VAArg, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::ExtractElement, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::InsertElement, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::ShuffleVector, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::LandingPad, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::Freeze, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::ExtractValue, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(2, Instruction::InsertValue, insts_garbage, false) ) {
      goto end;
    }

    if(insts_garbage.empty()) {
      goto end;
    }

    result = true;
  
end:
    return result;
  }

  bool third_step_2(std::vector<CustomFunction> &custom_functions, std::vector<Instruction *> &insts_garbage) {
    bool result = false;

    if(!custom_functions[0].is_commutative_instruction_in_block(4, insts_garbage, true) ||
        !custom_functions[0].is_associative_instruction_in_block(4, insts_garbage, true) ||
        !custom_functions[0].is_nilpotent_instruction_in_block(4, insts_garbage, false) ||
        !custom_functions[0].is_idempotent_instruction_in_block(4, insts_garbage, false) ||
        !custom_functions[0].is_opcode_in_block(4, Instruction::Mul, insts_garbage, false)) {
      goto end;
    }

    if(insts_garbage.empty()) {
      goto end;
    }

    result = true;

end:
    return result;
  }

  bool third_step_3(std::vector<CustomFunction> &custom_functions) {
    bool result = false;

    
    if(!custom_functions[0].is_block_subset_of(2, 4)) {
      goto end;
    }
    
    if(!custom_functions[0].is_block_subset_of(3, 6)) {
      goto end;
    }
    if(!custom_functions[0].is_blocks_equivalent(2, 6) || !custom_functions[0].is_blocks_equivalent(6, 9) ||
        !custom_functions[0].is_blocks_equivalent(9, 12)) {
      goto end;
    }
    if(!custom_functions[0].is_blocks_equivalent(4, 7) || !custom_functions[0].is_blocks_equivalent(7, 10) ||
        !custom_functions[0].is_blocks_equivalent(10, 13)) {
      goto end;
    }
    if(!custom_functions[0].is_blocks_equivalent(5, 8) || !custom_functions[0].is_blocks_equivalent(8, 11) ||
        !custom_functions[0].is_blocks_equivalent(11, 15)) {
      goto end;
    }
    result = true;

end:
    return result;

  }
  
  bool third_step(std::vector<CustomFunction> &custom_functions) {
    bool result = false;
    std::vector<Instruction *> block_1_mem_instruction;
    std::vector<Instruction *> block_8_mem_instruction;
    std::vector<Instruction *> block_11_mem_instruction;
    std::vector<Instruction *> insts_garbage;
    Instruction *load_inst = NULL;
    Instruction *get_elementptr_inst = NULL;
    Instruction *store_inst = NULL;
    Instruction *icmp_inst = NULL;
    Instruction *add_inst = NULL;

    result = third_step_0(custom_functions, block_1_mem_instruction, block_8_mem_instruction, block_11_mem_instruction);
    if(!result)
      goto end;

    load_inst = block_1_mem_instruction[0];

    // remove all loads from block
    if(!custom_functions[0].is_opcode_in_block(8, load_inst->getOpcode(), block_8_mem_instruction, false)) {
      goto end;
    } 

    // remove all loads from block
    if(!custom_functions[0].is_opcode_in_block(11, load_inst->getOpcode(), block_11_mem_instruction, false)) {
      goto end;
    } 
    
    store_inst = block_8_mem_instruction[0];

    get_elementptr_inst = block_11_mem_instruction[0];

    result = third_step_1(custom_functions, insts_garbage);    
    if(!result)
      goto end;
    
    icmp_inst = insts_garbage[0];

    insts_garbage.clear();
    result = third_step_2(custom_functions, insts_garbage);
    if(!result)
      goto end;
    
    add_inst = insts_garbage[0];

    result = third_step_3(custom_functions);
    if(!result)
      goto end;
    

    if(!third_step_4(custom_functions, 0, 3, icmp_inst, CmpInst::ICMP_UGT)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 0, 6, icmp_inst, CmpInst::ICMP_ULT)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 0, 9, icmp_inst, CmpInst::ICMP_UGT)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 0, 12, icmp_inst, CmpInst::ICMP_ULT)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 1, 4, add_inst, CmpInst::FCMP_FALSE,-1)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 1, 7, add_inst, CmpInst::FCMP_FALSE, 1)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 1, 10, add_inst, CmpInst::FCMP_FALSE,-1)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 1, 13, add_inst, CmpInst::FCMP_FALSE, 1)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 2, 5, store_inst, CmpInst::FCMP_FALSE, 0)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 2, 8, store_inst, CmpInst::FCMP_FALSE, 1)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 2, 11, store_inst, CmpInst::FCMP_FALSE, 2)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 2, 15, store_inst, CmpInst::FCMP_FALSE, 3)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 3, 4, get_elementptr_inst, CmpInst::FCMP_FALSE, 0)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 3, 7, get_elementptr_inst, CmpInst::FCMP_FALSE, 0)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 3, 10, get_elementptr_inst, CmpInst::FCMP_FALSE, 0)){
      goto end;
    }
    
    if(!third_step_4(custom_functions, 3, 13, get_elementptr_inst, CmpInst::FCMP_FALSE, 0)){
      goto end;
    }
    
    insts_garbage.clear();
    if(!custom_functions[0].is_opcode_in_block(14, Instruction::Br, insts_garbage, true)) {
      goto end;
    }

    insts_garbage.clear();
    if(!custom_functions[0].is_opcode_in_block(16, Instruction::Ret, insts_garbage, true)) {
      goto end;
    }

    result = true;

end:
    return result;
  }


  struct custom_pass: public PassInfoMixin<custom_pass> {
   
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
      bool valid_0 = false, valid_1 = false, valid_2 = false;
      std::vector<CustomFunction> custom_functions;
      std::vector<Instruction *> get_direction_block_0_call;

      for(Function &F : M) {
        if(!F.isDeclaration()) {
          StringRef function_name = F.getName();
          if(function_name == "chose_direction" || function_name == "get_direction" || function_name == "main") 
                custom_functions.emplace_back(F);
        }
      }
      // 0 => chose_direction
      // 1 => get_direction
      // 2 => main
      if(custom_functions.size() != 3) {
        goto end;
      }

      valid_0 = first_step(custom_functions, get_direction_block_0_call);
      if(valid_0)
        outs() << "[+] First step succeeded\n";
      

      valid_1 = second_step(get_direction_block_0_call);
      if(valid_1)
        outs() << "[+] Second step succeeded\n";

      valid_2 = third_step(custom_functions);
      if(valid_2)
        outs() << "[+] Third step succeeded\n";


      // Check all icmp from block 3, 6, 9, 12 
      // chose_direction 
      // block 1 => load, icmp
      // 
      // block 1 subset of block2 =>  check for load
      // 
      // block 2 => load, zext, icmp => for icmp WARN do not check for zext not worth
      //
      // block 3 => zext, icmp 
      //
      // block 3 subset of block2 
      //
      // block 4 => add, zext, load, zext, getelementptr, load, icmp
      //
      // block 2 subset of block 4 => WARN we do know zext, load, zext, load, icmp
      // extract after check those opcode
      //
      // block 5 => trunc, store, load, add, store, zext, getelementptr, store
      //
      // block 2 => block 6 => block 9 => block 12
      //
      // block 3 ugt => 6 ult => 9 ugt => 12 ult  check icmp ugt or ult
      //
      // block 4 add -1 => block 7 1 => block 10 -1 => block 14 1  
      //
      // block 5 store 0 => block 8 store 1 => block 11  store 2 => block 15 store 3 
      //
      // block 5 WARN do not check for trunc
      // block 8 check for store
      // block 11 extract trunc, store => block 11 is subset of block 7 check for getelementptr g_map
      // block 15 extract trunc, store => block 15 is subset of block 10 check for add
      // collect all add and check 
      
      
end:
      if(valid_0 && valid_1 && valid_2) {
        std::ifstream file("flag.txt");
        if(!file.is_open()) {
          errs() << "[-] Call an admin it shouldn't be the case \n";
        } else {
          std::stringstream buffer;
          buffer << file.rdbuf();
          outs() << "[+] Good job here is your flag: " << buffer.str() << "\n";
        }
        
      } else {
        outs() << "[-] Nope\n";
      }
      return PreservedAnalyses::all();
    }

    static bool isRequired() {
      return true;
    }
  
  };
}

PassPluginLibraryInfo get_pass_plugin_info() {
  const auto callback = [](PassBuilder &PB) {
    PB.registerPipelineParsingCallback(
     [&](StringRef name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
        MPM.addPass(hero::custom_pass());
        return true;
    });
  };
  return {LLVM_PLUGIN_API_VERSION, "Hero LLVM", "0.0.2", callback};
};

extern "C" __attribute__((visibility("default"))) LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return get_pass_plugin_info();
}
