#include "challenge_state.h"
#include "stage_1_pass.h"
#include "stage_2_pass.h"
#include "stage_3_pass.h"
#include "stage_4_pass.h"
#include "stage_5_pass.h"
#include "llvm/Passes/PassBuilder.h"
#include <llvm/ADT/IntrusiveRefCntPtr.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/Mangling.h>
#include <llvm/ExecutionEngine/Orc/Shared/ExecutorAddress.h>
#include <llvm/ExecutionEngine/Orc/Shared/ExecutorSymbolDef.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/LLVMContext.h>
#include <memory>
using namespace llvm;
using namespace llvm::orc;

static bool run_pipeline_and_publish(LLJIT &jit_builder, JITDylib &jd_secrets, JITDylib &jd_sandbox,
                                  std::unique_ptr<Module> &M, std::unique_ptr<LLVMContext> &ctx_player, ChallengeState &challenge_state) {
  PassBuilder PB;
  LoopAnalysisManager LAM; FunctionAnalysisManager FAM; CGSCCAnalysisManager CGAM; ModuleAnalysisManager MAM;
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  ModulePassManager MPM = PB.buildPerModuleDefaultPipeline(OptimizationLevel::O0);

  FunctionPassManager FPM;
  FPM.addPass(LoopSimplifyPass());
  FPM.addPass(LCSSAPass());
  // WARN we don't really give a fuck if the challenger want to read from memory directly to find the flag because
  // he would have to validate every step before his code would be execute. 
  FPM.addPass(stage1(challenge_state, /*optional callee=*/"swap_me"));
  FPM.addPass(stage2(challenge_state));
  FPM.addPass(stage3(challenge_state));
  FPM.addPass(stage4(challenge_state));
  FPM.addPass(stage5(challenge_state));
  MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

  MPM.run(*M, MAM);
  // printing IR after llvm passes
  // for (auto &F : *M) {
  //   if (!F.isDeclaration()) {
  //     errs() << "Function in player IR: " << F.getName()
  //            << "\n";
  //     F.print(errs(), nullptr);
  //   }
  // }
  if(!check_state(challenge_state)) {
    return false;
  }
  // TODO clean var setup
  // Conditionally publish secrets factories into JD_Sandbox
  ExecutionSession &execution_session = jit_builder.getExecutionSession();
  MangleAndInterner Mangle(execution_session, jit_builder.getDataLayout());
  SymbolMap SM;

  auto publish_fn = [&](const char *name) {
    auto Sym = jit_builder.lookup(jd_secrets, name);
    // TODO change this
    if (!Sym) { consumeError(Sym.takeError()); return; }

    SM[Mangle(name)] = ExecutorSymbolDef(Sym.get(), JITSymbolFlags::Exported);
  };

  // Publishing is not necessary there is no memory protection between two JIT session
  // But it could be a good hint
  if(challenge_state.stage1) publish_fn("secrets_stage0_factory");
  if(challenge_state.stage1) publish_fn("secrets_stage1_factory");
  if(challenge_state.stage2) publish_fn("secrets_stage2_factory");
  if(challenge_state.stage3) publish_fn("secrets_read64_at");
  if(challenge_state.stage5) {
    void *puts_addr = reinterpret_cast<void *>(&puts);
    ExecutorAddr puts_exec_addr = ExecutorAddr::fromPtr(puts_addr);
    SM[Mangle("puts")] = ExecutorSymbolDef(puts_exec_addr,
                       JITSymbolFlags::Exported);
  }

  if (!SM.empty()) cantFail(jd_sandbox.define(absoluteSymbols(std::move(SM))));
  
  ThreadSafeModule thread_safe_module(std::move(M), std::move(ctx_player));
  BAILOUT(jit_builder.addIRModule(jd_sandbox,
                std::move(thread_safe_module)));
  // publish check function
  cantFail(jit_builder.lookup(jd_sandbox, "check"));

  return true;
}
