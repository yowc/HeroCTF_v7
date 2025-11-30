#include <cstdio>
#include <llvm/ExecutionEngine/JITSymbol.h>
#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/Shared/ExecutorAddress.h>
#include <llvm/ExecutionEngine/Orc/Shared/ExecutorSymbolDef.h>
#include <llvm/Support/Casting.h>
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/ExecutionEngine/Orc/ThreadSafeModule.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/Instructions.h"

#include <memory>
#include <string>
#include <fstream>
#include <seccomp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#include "driver_pipeline.cpp"
#include "challenge_state.h"

using namespace llvm;
using namespace llvm::orc;

std::unique_ptr<Module> load_ir_file(const std::string &path,
                                   LLVMContext &ctx) {
  SMDiagnostic err;
  std::unique_ptr<Module> M = parseIRFile(path, err, ctx);
  if(!M) {
    exit(1);
  }
  return M;
}

static uint64_t get_rand_64() {
    uint64_t val = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open(/dev/urandom)");
        return 0; // fallback
    }
    if(read(fd, &val, sizeof(val)) != sizeof(val)) {
        perror("read(/dev/urandom)");
        val = 0; // fallback
    }
    close(fd);
    return val;
}

static std::string read_flag_from_file(const std::string &path) {
    std::ifstream f(path);
    if(!f) {
        errs() << "Could not open flag file: " << path << "\n";
        return "CTF{missing_flag}, contact admin";
    }
    std::string flag;
    std::getline(f, flag);
    return flag;
}

bool patch_secret_flag(Module &M, const std::string &flag_path) {
    LLVMContext &ctx = M.getContext();

    if(GlobalVariable *g_random_value = M.getGlobalVariable("g_random_value")) {
        uint64_t rand_64 = get_rand_64();
        if(!rand_64) {
            return false;
        }
        Constant *constant = ConstantInt::get(Type::getInt64Ty(ctx), rand_64);
        g_random_value->setInitializer(constant);
        g_random_value->setConstant(true); // optional
    }

    if(GlobalVariable *flag_str = M.getGlobalVariable("flag_str")) {
        std::string flag = read_flag_from_file(flag_path);
        Constant *new_flag = ConstantDataArray::getString(ctx, flag, true);
        flag_str->setInitializer(new_flag);
    }
    return true;
}

int install_seccomp_filter_do_not_reverse() {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);

  if(!ctx) {
    errno = ENOMEM;
    return -1;
  }

  // allow exit syscalls (so process can exit cleanly)
  if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) goto fail;
  if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) < 0) goto fail;

  // Allow write(fd == 1)
  if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                       SCMP_CMP64(0, SCMP_CMP_EQ, STDOUT_FILENO, 0)) < 0) goto fail;
  // Allow writev(fd == 1)
  if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1,
                       SCMP_CMP64(0, SCMP_CMP_EQ, STDOUT_FILENO, 0)) < 0) goto fail;
  if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                       SCMP_CMP64(0, SCMP_CMP_EQ, STDERR_FILENO, 0)) < 0) goto fail;
  // Allow writev(fd == 1)
  if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1,
                       SCMP_CMP64(0, SCMP_CMP_EQ, STDERR_FILENO, 0)) < 0) goto fail;

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);

  // could but not needed syscalls
  // seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  // seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
   
  if(seccomp_load(ctx) < 0) goto fail;

  seccomp_release(ctx);
  return 0;
fail:
  seccomp_release(ctx);
  return -1;
}

int main(int argc, char **argv) {
  InitLLVM X(argc, argv);
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();

  // TODO edit this shit finish clean var setup
  if (argc < 2) {
    errs() << "Usage: " << argv[0] << " <emit_file.ll>\n";
    return 1;
  }
  std::string playerPath = argv[1]; // WARN always clang -O1 -S -emit-llvm player.c -o player.ll before running it
  std::string secretPath = "src/secret_ir.ll";
  Expected<std::unique_ptr<LLJIT>> jit_builder_err = nullptr;
  std::unique_ptr<LLJIT> jit_builder = nullptr;

  // Build LLJIT
  jit_builder_err = LLJITBuilder().create();
  if(!jit_builder_err) BAILOUT(jit_builder_err.takeError());
  jit_builder = std::move(*jit_builder_err);
  auto &jit_ref = *jit_builder;

  // Create JITDylibs
  auto jd_tmp = jit_ref.createJITDylib("JD_Secrets");
  if(jd_tmp.takeError()) BAILOUT(jd_tmp.takeError());
  
  JITDylib &jd_secrets = jd_tmp.get();

  jd_tmp = jit_ref.createJITDylib("JD_Sandbox");
  if(jd_tmp.takeError()) BAILOUT(jd_tmp.takeError());

  JITDylib &jd_player = jd_tmp.get();

  // Set link order: sandbox first, then secrets
  jd_player.setLinkOrder({
      {&jd_player, JITDylibLookupFlags::MatchExportedSymbolsOnly},
      {&jd_secrets, JITDylibLookupFlags::MatchExportedSymbolsOnly}});

  auto ctx_secrets = std::make_unique<LLVMContext>();
  auto m_secrets = load_ir_file(secretPath, *ctx_secrets);
  bool patch_result = patch_secret_flag(*m_secrets, "./flag.txt");
  if(!patch_result) {
      return 1;
  } 
  BAILOUT(jit_ref.addIRModule(jd_secrets,
                         ThreadSafeModule(std::move(m_secrets),
                                          std::move(ctx_secrets))));

  std::unique_ptr<LLVMContext> ctx_player = std::make_unique<LLVMContext>();
  std::unique_ptr<Module> m_player = load_ir_file(playerPath, *ctx_player);

  ChallengeState challenge_state;
  bool published = run_pipeline_and_publish(jit_ref, jd_secrets,jd_player, m_player, ctx_player, challenge_state);
  if(published) {
    if(install_seccomp_filter_do_not_reverse() != 0) {
        fprintf(stderr, "seccomp install failed: %s\n", strerror(errno));
        return 1;
    }
    ExecutorAddr Sym = cantFail(jit_ref.lookup(jd_player, "check"));
    using check_fn = int(*)(void);
    check_fn check = (check_fn)Sym.getValue();
    int res = check();
    errs() << "[+] check() returned " << res << "\n";
  } else {
      errs() << "[-] Nope\n";
  }

  return 0;
}

