#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/IR/Analysis.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Compiler.h>
#include <fstream>
#include <sstream>

using namespace llvm;

namespace hero {

  struct custom_pass: public PassInfoMixin<custom_pass> {
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
      bool valid_0 = false;
      bool valid_1 = false;
      bool valid_2 = false;
      if("SWORD_OF_THE_HERO" == F.getName()) {
        valid_0 = true;
      }
      
      auto nargs = 0;
      for (auto &arg : F.args()) {
        if(arg.getType()->getTypeID() == llvm::Type::IntegerTyID) {
          nargs++;
        }
      }
      if(nargs == 3) {
        valid_1 = true;
      }
      if(F.getReturnType()->getTypeID() == llvm::Type::PointerTyID) {
        valid_2 = true;
      }
      if(valid_0 && valid_1 && valid_2) {
        std::ifstream file("flag.txt");
        if(!file.is_open()) {
          errs() << "[-] Call an admin it shouldn't be the case \n";
        } else {
          std::stringstream buffer;
          buffer << file.rdbuf();
          errs() << "[+] Good job here is your flag: " << buffer.str() << "\n";
        }
        
      } else {
        errs() << "[-] Nope\n";
      }
      return PreservedAnalyses::all();
    }
  };
}

PassPluginLibraryInfo get_pass_plugin_info() {
  const auto callback = [](PassBuilder &PB) {
    PB.registerPipelineStartEPCallback([&](ModulePassManager & MPM, auto) {
    MPM.addPass(createModuleToFunctionPassAdaptor(hero::custom_pass()));
    return true;
  });
  };
  return {LLVM_PLUGIN_API_VERSION, "Hero LLVM", "0.0.1", callback};
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return get_pass_plugin_info();
}
