# The Obsidian Optimizer

### Category

Reverse

### Difficulty

Hard

### Author

Teddysbears

### Description

You have reached the forbidden sanctum of the compiler — where JITs whisper and globals shimmer in the dark. Here, passes can alter running code, conjuring functions at runtime.
Only the most disciplined minds can wield such power without corrupting themselves.

Note: The given archive contains a python script to send your payload to server.
Note: A Dockerfile is also in the archive in order to run the challenge as it is on the server.

TCP: `nc reverse.heroctf.fr 7000`

### Files

- [the_obsidian_optimizer.zip](the_obsidian_optimizer.zip)

### Write Up

This is the last challenge of the LLVM triptych.

We have the following archive `the_obsidian_optimizer.zip`:
```sh
Archive:  the_obsidian_optimizer.zip
   creating: the_obsidian_optimizer/
  inflating: the_obsidian_optimizer/Makefile
  inflating: the_obsidian_optimizer/the_obsidian_optimizer
 extracting: the_obsidian_optimizer/flag.txt
   creating: the_obsidian_optimizer/bin/
   creating: the_obsidian_optimizer/src/
  inflating: the_obsidian_optimizer/src/secret_ir.ll
  inflating: the_obsidian_optimizer/src/valid_pass.c
```

We have a Makefile that only emits the IR for valid_pass.c, a fake flag file, an IR file named secret_ir.ll, and a binary importing many libraries:

```sh
$ ldd the_obsidian_optimizer
	linux-vdso.so.1 (0x00007f5f27bef000)
	libseccomp.so.2 => /usr/lib/libseccomp.so.2 (0x00007f5f27b46000)
	libLLVM.so.21.1 => /usr/lib/libLLVM.so.21.1 (0x00007f5f1e400000)
	libstdc++.so.6 => /usr/lib/libstdc++.so.6 (0x00007f5f1e000000)
	libm.so.6 => /usr/lib/libm.so.6 (0x00007f5f1e2f2000)
	libgcc_s.so.1 => /usr/lib/libgcc_s.so.1 (0x00007f5f27b19000)
	libc.so.6 => /usr/lib/libc.so.6 (0x00007f5f1dc00000)
	libffi.so.8 => /usr/lib/libffi.so.8 (0x00007f5f27b0b000)
	libedit.so.0 => /usr/lib/libedit.so.0 (0x00007f5f27ad1000)
	libz.so.1 => /usr/lib/libz.so.1 (0x00007f5f27ab8000)
	libzstd.so.1 => /usr/lib/libzstd.so.1 (0x00007f5f1df1b000)
	libxml2.so.16 => /usr/lib/libxml2.so.16 (0x00007f5f1dacb000)
	/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f5f27bf1000)
	libncursesw.so.6 => /usr/lib/libncursesw.so.6 (0x00007f5f1deac000)
	libicuuc.so.78 => /usr/lib/libicuuc.so.78 (0x00007f5f1d800000)
	libicudata.so.78 => /usr/lib/libicudata.so.78 (0x00007f5f1b800000)
```

If we try to run the binary, nothing will happen. But if we run the Makefile, we get something:
```sh
$ ./the_obsidian_optimizer
Usage: ./bin/the_obsidian_optimizer <emit_file.ll>
$ ./the_obsidian_optimizer bin/emit.ll
[-] Nope
```

What does the binary do with our emitted IR?
When we opened the binary, we saw that it uses the path to our IR as follows: 
```c++
int main() {
  ...
  std::string::basic_string<std::allocator<char>>(v67, "bin/emit.ll", &v51);
  ...
  v5 = std::unique_ptr<llvm::LLVMContext>::operator*(v27);
  // IR loaded in v26 
  load_ir_file(v26, v67, v5);
  ...
    run_pipeline_and_publish(v22, v21, v20, v26, v27, v59)
  ...
}

__int64 __fastcall load_ir_file(__int64 a1, __int64 a2, __int64 a3) {
  llvm::ParserCallbacks::ParserCallbacks((llvm::ParserCallbacks *)s);
  llvm::parseIRFile(a1, v5[0], v5[1], v7, a3, s);
  llvm::ParserCallbacks::~ParserCallbacks((llvm::ParserCallbacks *)s);
}


```
Our IR code will be loaded and the result will be an argument to the `run_pipeline_and_publish` function.
When we cross-reference `load_ir_file`, we see that **src/secret_ir.ll** is also loaded and modified on the fly.
```c++
  std::string::basic_string<std::allocator<char>>(v66, "src/secret_ir.ll", &v50);
  load_ir_file(v33, v66, v4);
  v14 = std::unique_ptr<llvm::Module>::operator*(v33);
  std::string::basic_string<std::allocator<char>>(v60, "./flag.txt", &v32);
  v15 = patch_secret_flag(v14, v60);

  char __fastcall patch_secret_flag(llvm::Module *a1, __int64 a2) {
    ...
    Context = (llvm::Type *)llvm::Module::getContext(a1);
    llvm::StringRef::StringRef((llvm::StringRef *)v15, "g_random_value");
    GlobalVariable = (llvm::GlobalVariable *)llvm::Module::getGlobalVariable(a1, v15[0], v15[1], 0LL);
    ...
    rand_64 = get_rand_64();
    v7 = llvm::ConstantInt::get(Int64Ty, rand_64, 0LL);
    llvm::GlobalVariable::setInitializer(GlobalVariable, v7);
    llvm::GlobalVariable::setConstant(GlobalVariable, 1);
    ...
    llvm::StringRef::StringRef((llvm::StringRef *)v14, "flag_str");
    v6 = llvm::Module::getGlobalVariable(a1, v14[0], v14[1], 0LL);
    read_flag_from_file(v16, a2);
    llvm::StringRef::StringRef(v13, v16);
    String = llvm::ConstantDataArray::getString(Context, v13[0], v13[1], 1LL);
    llvm::GlobalVariable::setInitializer(v6, String);
  }
```
It gets the context of the IR code and searches for two globals: `g_random_value` and `flag_str`. It replaces their values with a random value and the value from the `flag.txt` file, respectively.

We need to check the `src/secret_ir.ll` code. 
```c
@flag_str = global [16 x i8] c"Hero{FAKE_FLAG}\00", align 8
@g_random_value = global i64 323232, align 8
@g_table_size = global i64 3, align 8
@jump_table = internal global [4 x ptr] [ptr null, ptr null, ptr null, ptr @get_flag], align 8
...
define i64* @secrets_stage0_factory(i64 %a, i64 %b, i64 %c, i64 %d) {
  ...
}
define i64* @secrets_stage2_factory(i64 %magic) {
  ...
}
define i64 @secrets_read64_at(i64 %idx) {
  ...
}
define void @get_flag(i64 %val) {
  ...
}
```
This file contains multiple function definitions and 4 global variables. At this point, we only know that two global variables will be modified.
The binary creates 2 **llvm::orc::JITDylib** instances, which represent JIT dynamic libraries capable of running IR code.
To summarize quickly: It creates 2 **JITDylib** instances with our IR (`JD_Sandbox`) and secret_ir (`JD_Secrets`). It also creates an **LLJIT** from which it will execute a `check()` function (probably from our IR). Finally, it initializes a ChallengeState object. The `run_pipeline_and_publish(v22, v21, v20, v26, v27, v59)` takes all these arguments as: 
```C++
// v22 LLJIT
// v21 JITDylib
// v20 JITDylib
// v26 our IR
// v27 LLVMContext
// v59 ChallengeState
run_pipeline_and_publish(v22, v21, v20, v26, v27, v59);

// ChallengeState:
void __fastcall ChallengeState::ChallengeState(challenge_state *this)
{
  this->byte0 = 0;
  this->byte1 = 0;
  this->byte2 = 0;
  this->byte3 = 0;
  this->byte4 = 0;
  std::string::basic_string(&this->string_0);
  std::string::basic_string(&this->string_1);
  std::string::basic_string(&this->string_2);
  std::string::basic_string(&this->string_3);
  std::string::basic_string(&this->string_4);
  std::string::basic_string(&this->string_5);
}
```
First, it sets up the environment for LLVM passes and registers module analysis. It runs some built-in passes and 5 custom passes: `stage1`, `stage2`, `stage3`, `stage4`, and `stage5`. After that, it checks if 5 booleans in ChallengeState are true. If not, the function returns false and we won't execute the code from our IR. Otherwise, it will share symbols between JITDylib instances and, if the booleans are true, also publish the `puts` function.

So we must analyze the five custom passes to understand how to set those booleans to true. All these passes work with the same context, which is the `check` function.

Stage1 takes one more argument than the other passes: a string **"swap_me"**.

First, this stage checks the first loop found in the `check` function, and if the upper bound is **42**, it continues. After that, it parses all instructions from the loop. An IR loop can contain `guard`, `preheader`, `header`, `exiting`, `latch`, and `exit`. It searches for a function call—if the name matches **"swap_me"**, it will search for a condition in the block right before this one and its predicate, and extract its value. If this value is **41**, then we're almost there. It will replace the `swap_me` function with `secrets_stage0_factory`. There is one last check on the function call result: if it is stored in a global variable, we will get our first success string **"[Stage1] succeeded"**. 
```c++
llvm::PreservedAnalyses *__fastcall stage1::run(
        llvm::PreservedAnalyses *a1,
        _BYTE **a2,
        llvm::Function *a3,
        __int64 a4)
{
  ...
  // search the for the first loop of check function
  FirstLoop = findFirstLoop(v52);
  ...
  // loop upper_bound check
  if ( FirstLoop && (loop_upper_bound_check(FirstLoop, 42LL) & 1) != 0 )
  ...
    // parse all instructions from loop blocks
    while ( v38 != (llvm::BasicBlock **)v37 ) {
      while ( (llvm::operator!=(&v76, &v74) & 1) != 0 ) {
        // check if the name is the same as swap_me
        CalledFunction = (llvm::Value *)llvm::CallBase::getCalledFunction(v33);
        Name = llvm::Value::getName(CalledFunction);
        llvm::operator==(Name, v31, v62[0], v62[1])
        // check the condition right before the call
        llvm::BasicBlock::getSinglePredecessor(v36);
        llvm::BasicBlock::getTerminator(SinglePredecessor)
        llvm::BranchInst::isConditional(v28)
        llvm::ICmpInst::getCmpPredicate(v27)
        // extract the contant value from the predicate
        ZExtValue = llvm::APInt::getZExtValue((llvm::APInt *)v71)
      }
    }
  // if not 41 then fail
  if ( ZExtValue != 41 )
    goto LABEL_28;

  ... 
  // check if the result of the function is stored in a global 
  is_stored = (llvm::Value *)find_global_where_value_is_stored(v49);
  // Complexe strategy to replace the swap_me function with the secrets_stage0_factory ones
  llvm::IRBuilderBase::CreateCall((unsigned int)v80, v57, v58, v55, v56, (unsigned int)v68, 0LL);
  llvm::Value::replaceAllUsesWith(v49, v41);
  v66 = llvm::Instruction::eraseFromParent(v49);
  if ( is_stored ) {
    ...
    // success string
    llvm::raw_ostream::operator<<(v20, "[Stage1] succeeded\n");
    // store true in first ChallengeState boolean
    **a2 = 1;
    // gets its name and store it to string0
    v54[0] = llvm::Value::getName(is_stored);
    llvm::StringRef::str[abi:cxx11](v78, v54);
    std::string::operator=(*a2 + 8, v78);
    ...
  }
}
```
Let's update our `valid_pass` to check if it works:
```c
// it must compile; must define the symbol
extern void* swap_me();

// define a global to get the result
void *result_0;

// inside check function
int check() {
  // loop upper bound value 42
  for(int i = 0; i < 42; i++) {
    // previous block value if predicate const 41
    if(i == 41) {
      // save result and use the swap_me keyword
      result_0 = swap_me();
    }
  }
  return 0;
}

int main(void) {
  return 0;
}
```
We should check the code of the function swapped, which lives inside `secret_ir.ll`: 
```c
// takes 4 arguments
define i64* @secrets_stage0_factory(i64 %a, i64 %b, i64 %c, i64 %d) {
entry:
  %cmp_1 = icmp eq i64 %a, 1
  br i1 %cmp_1, label %next_2, label %bad

next_2:
  %cmp_2 = icmp eq i64 %b, 2
  br i1 %cmp_2, label %next_3, label %bad

next_3:
  %cmp_3 = icmp eq i64 %c, 3
  br i1 %cmp_3, label %next_4, label %bad

next_4:
  %cmp_4 = icmp eq i64 %d, 4
  br i1 %cmp_4, label %ok, label %bad
// check a == 1 && b == 2 && c == 3 && d == 4
ok:
// if valid, return a pointer to the @secrets_stage1_factory function
  %p = bitcast ptr @secrets_stage1_factory to i64*
  ret i64* %p
// else return a null ptr
bad:
  ret ptr null
}
```
Just update the code to make it return the function pointer:
```c
extern void* swap_me(int, int, int, int);
...
  result_0 = swap_me(1, 2, 3, 4);
```
If we compile and re-run our binary: 
```sh
[Stage1] succeeded
[-] Nope
```
**Stage 2:**

The first thing it checks is whether the previous boolean and string are set.
```c++
if ( (**(_BYTE **)a2 & 1) != 0 && (std::string::empty(*(_QWORD *)a2 + 8LL) & 1) == 0 )
```
After that, it searches for a loop with a lower bound of 0 and an upper bound of 0x1337. 
```c++
if ( (loop_upper_bound_check(*v64, 0x1337LL) & 1) != 0 && (loop_lower_bound_check(v37, 0LL) & 1) != 0 )
```

It loops over instructions from the preheader. It searches for a store instruction and gets its second operand.
The preheader from the previous loop in stage 1 looks like: 
```c
  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  br label %2
```
The **store** instruction's second operand represents the loop index. After that, it checks loop blocks for a **load** instruction with a pointer operand that is a global. If the name is the same as the one saved in stage 1, it will save it to a variable. After that, it searches for a **conditional branch** using the loop index. If found, it checks if the predicate type is **ICMP_EQ** and compares the value to a constant **-1**. Finally, if it finds our previously saved global as a call instruction, it will remove the current **conditional branch**. As with the previous stage, it checks that the call value is stored in a global.

```c++
// get loop index
Operand = llvm::StoreInst::getOperand(v47, 1u);

// checks for global
PointerOperand = llvm::LoadInst::getPointerOperand(v32);
v31 = (llvm::Value *)llvm::dyn_cast<llvm::GlobalVariable,llvm::Value>(PointerOperand);

// a condition with loop index and -1
Condition = llvm::BranchInst::getCondition(v25);
v66 = llvm::CmpInst::getOperand(v24, 1u);
v43 = (llvm::Value *)llvm::CmpInst::getOperand(v24, 0);
llvm::UnaryInstruction::getOperand(v41, 0) == Operand
llvm::CmpInst::getPredicate(v24) == 32
llvm::APInt::APInt((llvm::APInt *)v67, BitWidth, 0xFFFFFFFFFFFFFFFFLL, 1, 0);

// check for the global used as callinst and where it is stored
v58[0] = llvm::Value::users(v50);
v38 = llvm::dyn_cast<llvm::CallInst,llvm::User>(v22);
is_stored = (llvm::Value *)find_global_where_value_is_stored(v50);
```
This time, the function called is the previous function pointer obtained from `secrets_stage0_factory`. So to call it correctly, we should look at the code for it.
```c
define i64* @secrets_stage1_factory(i64 %a) {
entry:
  %cmp = icmp eq i64 %a, -1
  br i1 %cmp, label %ok, label %bad
// if a equals -1, return the secrets_stage2_factory function pointer
ok:
  %p = bitcast ptr @secrets_stage2_factory to i64*
  ret i64* %p
// else return null ptr
bad:
  ret ptr null
}
```
The C code we can generate from this information is as follows: 
```c
// to manage -1 as int64_t 
#include <stdint.h>

// define the type to compile the with dynamic function pointer
typedef void* (*result_0_type)(int64_t);
...
void *result_1;
...
// the loop 
  for(int i = 0; i < 0x1337; i++) {
    // the condition using loop index and -1
    if(i == -1) {
      // calling result_0 global and storing it as another global
      result_1 = ((result_0_type)(result_0))(-1);
    }
  }
...
```
As you can imagine, when our IR code executes, the condition will never be true. But as a reminder, it will remove the conditional branch, which will cause the function to execute.
If we compile and re-run our binary: 
```sh
[Stage1] succeeded
[Stage2] succeeded
[-] Nope
```
OK, stage 2 is clear. For the next stage, we'll go into less detail.

**Stage 3:**

- Check if the previous stage is valid
```c++
  if ( (*(_BYTE *)(*(_QWORD *)a2 + 1LL) & 1) != 0 && (std::string::empty(*(_QWORD *)a2 + 40LL) & 1) == 0 )
```
- Check if the loop has a lower bound of 0xFFFFFFFF and an upper bound of 0x1FFFFFFFF
```c++
if ( (loop_upper_bound_check(*v60, 0x1FFFFFFFFLL) & 1) != 0
  && (loop_lower_bound_check(v32, 0xFFFFFFFFLL) & 1) != 0 )
```
- As before, get the loop index
```c++
v41 = (llvm::StoreInst *)llvm::dyn_cast<llvm::StoreInst,llvm::Instruction>(v42);
Operand = (llvm::Value *)llvm::StoreInst::getOperand(v41, 1u);
```
- Also check the global call
```c++
PointerOperand = llvm::LoadInst::getPointerOperand(v27);
v26 = (llvm::Value *)llvm::dyn_cast<llvm::GlobalVariable,llvm::Value>(PointerOperand);
Name = llvm::Value::getName(v26);
```
- Check loop index users and modify those impossible conditions
```c++
v56[0] = llvm::Value::users(Operand);
v33 = llvm::CmpInst::getOperand(v21, 1u);
v20 = (llvm::ConstantInt *)llvm::dyn_cast<llvm::ConstantInt,llvm::Value>(v33);
// 2 cases inside the loop:
// truncate the value of the condition
if ( llvm::ConstantInt::getZExtValue(v20) == 0xFEEDFACFLL )
llvm::Twine::Twine((llvm::Twine *)v63, "custom_0");
Trunc = (llvm::Value *)llvm::IRBuilderBase::CreateTrunc(
                          (llvm::IRBuilderBase *)v74,
                          v22,
                          Int32Ty,
                          (const llvm::Twine *)v63,
                          0,
                          0);
llvm::CmpInst::setOperand(v21, 0, Trunc);

// create a trunc, SExt operand
// so truncate the value and get the signed version
if ( llvm::ConstantInt::getSExtValue(v20) == -1 )
llvm::Twine::Twine((llvm::Twine *)v62, "custom_1");
v19 = (llvm::Value *)llvm::IRBuilderBase::CreateTrunc(
                        (llvm::IRBuilderBase *)v73,
                        v22,
                        Int32Ty,
                        (const llvm::Twine *)v62,
                        0,
                        0);
llvm::Twine::Twine((llvm::Twine *)v61, "custom_2");
SExt = (llvm::Value *)llvm::IRBuilderBase::CreateSExt(
                        (llvm::IRBuilderBase *)v73,
                        v19,
                        Int32Ty,
                        (const llvm::Twine *)v61);
v35 = (llvm::Value *)llvm::ConstantInt::get(Int32Ty, (llvm::Type *)0xFFFFFFFFFFFFFFFFLL, 1uLL, v14);
llvm::CmpInst::setOperand(v21, 0, SExt);
llvm::CmpInst::setOperand(v21, 1u, v35);
```
- Check the global store, etc.

The IR part looks like: 
```c
define i64* @secrets_stage2_factory(i64 %magic) {
entry:
// check the value 0x1feedfacf
  %cmp = icmp eq i64 %magic, 8571976399
  br i1 %cmp, label %ok, label %bad
// return pointer to secrets_read64_at
ok:
  %p = bitcast ptr @secrets_read64_at to i64*
  ret i64* %p
// else return null ptr
bad:
  ret ptr null
}
```
The code to make this stage work should look like: 
```c
typedef void* (*result_1_type)(int64_t);
...
void *result_2;
...
  for(int64_t i = 0xFFFFFFFF; i < 0x1FFFFFFFF; i++) {
    if(i == 0xfeedfacf) {
      if(i < -1){
        result_2 = ((result_1_type)(result_1))(0x1feedfacf);
      }
    }
  }
```
Then the output is the following: 
```sh
[Stage1] succeeded
[Stage2] succeeded
[Stage3] succeeded
[-] Nope
```
**Stage 4** is a bit simpler:

- Validate the previous stage
```c++
if ( (*(_BYTE *)(*(_QWORD *)a2 + 2LL) & 1) != 0 && (std::string::empty(*(_QWORD *)a2 + 72LL) & 1) == 0 )
```
- Search for 3 global variables using the call to the `result_2` function pointer. 
```c++
// get globals from module
Parent = (llvm::Module *)llvm::GlobalValue::getParent(a3);
v37[0] = llvm::Module::globals(Parent);

// check name
Name = llvm::Value::getName(v18);

// check users of this variable
v33[0] = llvm::Value::users(v22);

// check how it is used
v14 = llvm::dyn_cast<llvm::LoadInst,llvm::User>(v15);

// if in a call, then check the store
if ( llvm::dyn_cast<llvm::CallInst,llvm::Value>(NextNode) ) {

  is_stored = find_global_where_value_is_stored(NextNode);
  // second stored
  v23 = (llvm::Value *)is_stored;

  // third stored
  v25 = (llvm::Value *)is_stored;

  // first stored
  v24 = (llvm::Value *)is_stored;

  // increment each time a new one is found
  ++v20;
}
// if equals 3, then we succeeded
if ( v20 == 3 )
  llvm::raw_ostream::operator<<(v10, "[Stage4] succeeded \n");
```
If we check the code for this function in the IR: 
```c
...
@g_random_value = global i64 323232, align 8

@g_table_size = global i64 3, align 8
@jump_table = internal global [4 x ptr] [ptr null, ptr null, ptr null, ptr @get_flag], align 8
...
define i64 @secrets_read64_at(i64 %idx) {
entry:
  %cmp = icmp ult i64 %idx, 24
  br i1 %cmp, label %ok, label %bad

// if idx == 0, return the g_random_value modified on the fly earlier
ok:
  %is0 = icmp eq i64 %idx, 0
  br i1 %is0, label %r0, label %next_0

r0:
  %v0 = load i64, ptr @g_random_value
  ret i64 %v0

// if idx == 8, return the g_table_size, which equals 3
next_0:
  %is8 = icmp eq i64 %idx, 8
  br i1 %is8, label %size, label %next_1

size:
  %table_size = load i64, ptr @g_table_size
  ret i64 %table_size

// if idx == 16, return the g_jump_table pointer
next_1:
  %is16 = icmp eq i64 %idx, 16
  br i1 %is16, label %jt, label %bad

jt:
  %jtptr = ptrtoint ptr @jump_table to i64
  ret i64 %jtptr

// else return 0
bad:
  ret i64 0
}
```
The code that validates these conditions: 
```c
typedef void* (*result_2_type)(uint64_t);
uint64_t g_random_value = 0;
uint64_t g_table_size = 0;
uint64_t g_jump_table = 0;
...
  g_random_value = (uint64_t)((result_2_type)(result_2))(0);
  g_table_size = (uint64_t)((result_2_type)(result_2))(8);
  g_jump_table = (uint64_t)((result_2_type)(result_2))(16);
...
```
Try with this code: 
```sh
[Stage1] succeeded
[Stage2] succeeded
[Stage3] succeeded
[Stage4] succeeded
[Stage4] succeeded
[-] Nope
```
One more stage to go and we're done.

**Stage 5:**

The last stage is the most difficult to understand because there is more code than before, but if we focus on simple conditions, it's manageable.

- As with all stages, it checks that the previous stage is valid.
```c++
if ( (*(_BYTE *)(*(_QWORD *)a2 + 3LL) & 1) == 0
    || (std::string::empty(*(_QWORD *)a2 + 104LL) & 1) != 0
    || (std::string::empty(*(_QWORD *)a2 + 136LL) & 1) != 0
    || (std::string::empty(*(_QWORD *)a2 + 168LL) & 1) != 0 )
```
- Get all previous global variable references
- Check that the loop uses g_table_size as the loop max index + 1
```c++
llvm::User::getOperand(v50, 0) == Operand
llvm::User::getOperand(v49, 0) == v50
```
- Check that there is a condition where the loop index equals 3
```c++
llvm::APInt::operator!=(v87, 3LL)
```
- Check that there is a call to g_jump_table at the loop index with g_random_value as an argument
```c++
// check call instruction
CalledOperand = (llvm::Value *)llvm::CallBase::getCalledOperand(v47);
v46 = (llvm::Value *)llvm::Value::stripPointerCasts(CalledOperand);
// check that GetElementPtr is for g_jump_table at loop index
gep_in_same_block = (llvm::GetElementPtrInst *)find_gep_in_same_block(v46);
// global g_jump_table
v23 = llvm::GetElementPtrInst::getOperand(gep_in_same_block, 0);
// loop index
v24 = llvm::GetElementPtrInst::getOperand(gep_in_same_block, 1u);
if ( (llvm::Value *)llvm::LoadInst::getPointerOperand(v45) != v63 )
if ( llvm::LoadInst::getPointerOperand(v44) != Operand )
// check that the argument is g_random_value
if ( (llvm::CallBase::arg_empty(v47) & 1) != 0 )
ArgOperand = llvm::CallBase::getArgOperand(v47, 0);
v43 = (llvm::LoadInst *)llvm::dyn_cast<llvm::LoadInst,llvm::Value>(ArgOperand);
if ( !v43 || (llvm::Value *)llvm::LoadInst::getPointerOperand(v43) != v62 )
```
If we check the IR: 
```c
// the value to pass as a parameter to the get_flag function
@g_random_value = global i64 323232, align 8
// size too small to call get_flag directly
@g_table_size = global i64 3, align 8
// table with get_flag function ptr
@jump_table = internal global [4 x ptr] [ptr null, ptr null, ptr null, ptr @get_flag], align 8

// the function that we want to call to get the flag
define void @get_flag(i64 %val) {
entry:
// check the g_random_value against our arg
  %v = load i64, ptr @g_random_value
  %cmp = icmp eq i64 %val, %v
  br i1 %cmp, label %show, label %end

show:
// print the flag
  %ptr = getelementptr inbounds [25 x i8], ptr @flag_str, i64 0, i64 0
  call i32 @puts(ptr %ptr)
  br label %end

end:
  ret void
}
```
OK, we need to write the code to validate this stage:
```c
typedef void (*get_flag_t)(uint64_t);
// we had to update the type to make it compile
void** g_jump_table = 0;
// the loop header with the global + 1
  for(int i = 0; i < g_table_size + 1; i++) {
    // the condition that overlaps the array due to the size
    if(i == 3) {
      // the call with the loop index / g_random_value to print the flag
      ((get_flag_t)(g_jump_table[i]))(g_random_value);
    }
  }
```
We get the following output: 
```sh
[Stage1] succeeded
[Stage2] succeeded
[Stage3] succeeded
[Stage4] succeeded
Careful: due to optimization, the loop preheader could be merged with the previous block, so adding any check on global variables could help
[-] Nope
```
In fact, if we check our IR code, we get the following merge: 
```c
55:                                               ; preds = %51
  %56 = load ptr, ptr @result_2, align 8
  %57 = call ptr %56(i64 noundef 0)
  %58 = ptrtoint ptr %57 to i64
  store i64 %58, ptr @g_random_value, align 8
  %59 = load ptr, ptr @result_2, align 8
  %60 = call ptr %59(i64 noundef 8)
  %61 = ptrtoint ptr %60 to i64
  store i64 %61, ptr @g_table_size, align 8
  %62 = load ptr, ptr @result_2, align 8
  %63 = call ptr %62(i64 noundef 16)
  store ptr %63, ptr @g_jump_table, align 8
  store i64 0, ptr %5, align 8                   ; HERE loop preheader stores 0, so we need to de-optimize it
  br label %64
```
We will prevent the optimization with: 
```c
typedef void (*get_flag_t)(uint64_t);
// we had to update the type to make it compile
void** g_jump_table = 0;

// de-optimize the loop
if(!g_jump_table) return 1;

// the loop header with the global + 1
  for(int i = 0; i < g_table_size + 1; i++) {
    // the condition that overlaps the array due to the size
    if(i == 3) {
      // the call with the loop index / g_random_value to print the flag
      ((get_flag_t)(g_jump_table[i]))(g_random_value);
    }
  }
```
The final output is: 
```c
[Stage1] succeeded
[Stage2] succeeded
[Stage3] succeeded
[Stage4] succeeded
[Stage5] succeeded
[Stage4] succeeded
Hero{FAKE_FLAG}
[+] check() returned 0
```
It's strange that stage 4 succeeded twice, but we got the flag.

The final code looks like: 
```c
#include <stdint.h>

extern void* swap_me(int, int, int, int);
typedef void* (*result_0_type)(int64_t);
typedef void* (*result_1_type)(int64_t);
typedef void* (*result_2_type)(uint64_t);
typedef void* (*get_flag_t)(uint64_t);

void *result_0;
void *result_1;
void *result_2;

uint64_t g_random_value = 0;
uint64_t g_table_size = 0;
void** g_jump_table = 0;

int check() {
  for(int i = 0; i < 42; i++) {
    if(i == 41) {
      result_0 = swap_me(1, 2, 3, 4);
    }
  }
  for(int i = 0; i < 0x1337; i++) {
    if(i == -1) {
      result_1 = ((result_0_type)(result_0))(-1);
    }
  }
  for(int64_t i = 0xFFFFFFFF; i < 0x1FFFFFFFF; i++) {
    if(i == 0xfeedfacf) {
      if(i < -1){
        result_2 = ((result_1_type)(result_1))(0x1feedfacf);
      }
    }
  }

  g_random_value = (uint64_t)((result_2_type)(result_2))(0);
  g_table_size = (uint64_t)((result_2_type)(result_2))(8);
  g_jump_table = ((result_2_type)(result_2))(16);

  if(!g_jump_table) return 1;

  // the loop header with the global + 1 
  for(uint64_t i = 0; i < g_table_size + 1; i++) {
    // the condition which overlapp the array from the size
    if(i == 3) {
      // the call with the loop index / g_random_value to print the flag
      ((get_flag_t)(g_jump_table[i]))(g_random_value);
    }
  }


  return 0;
}

int main(void) {
  return 0;
}

```
### Flag

Hero{Y0u_dE53rVe_7He_0bS1Di4n_OpT1mIz3R_tI7l3}


