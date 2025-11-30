# Apprentice of the IR Forge

### Category

Reverse

### Difficulty

Easy

### Author

Teddysbears

### Description

Deep beneath the compiler’s citadel lies the IR Forge — a molten realm where runes of computation are shaped into order. Apprentice blacksmiths of logic come here to temper their skill and learn to read the language of transformations.
Will you be worthy of becoming an apprentice at the IR forge? 

Note: The given archive contains a python script to send your payload to server.
Note: A Dockerfile is also in the archive in order to run the challenge as it is on the server.

TCP: `nc reverse.heroctf.fr 7002`

### Files

- [forge.zip](forge.zip)

### Write Up

This is the first challenge of a triptych.
For this challenge, we have an archive `forge.zip`. When we decompress it, we get the following files:
```sh
Archive:  forge.zip
   creating: forge/
  inflating: forge/Makefile
 extracting: forge/flag.txt
   creating: forge/bin/
  inflating: forge/bin/apprentice_of_the_IR_forge.so
   creating: forge/src/
 extracting: forge/src/valid_pass.c
```
If we print the flag, we get the string: `Hero{FAKE_FLAG}`. We also see that there is an instance on the CTFd platform to submit something, which means we can test our solution locally before sending it to the server.

It's unusual to have a Makefile in a reverse engineering challenge, so let's check its contents:

```make
CC = clang

SRC = src/
BIN = bin/

VALID_PASS = valid_pass
LLVM_PASS = apprentice_of_the_IR_forge
LLVM_EMIT = emit

VPASS = $(SRC)$(VALID_PASS).c
OUT = $(BIN)$(VALID_PASS)
LIB = $(BIN)$(LLVM_PASS).so

EMIT = $(BIN)$(LLVM_EMIT).ll

$(EMIT): $(VPASS)
    $(CC) -O1 -emit-llvm -S $< -o $@

$(OUT): $(LIB)
    $(CC) -O1 -fpass-plugin=$< $(VPASS) -o $@

init:
    @echo "Running apprentice_of_the_IR_forge"
    @echo ---------------------------------
    mkdir -p bin

all: init $(EMIT) $(OUT)

clean:
    rm $(OUT) $(EMIT)
```

As we can see, it compiles `src/valid_pass.c` with clang while adding a custom LLVM pass `bin/apprentice_of_the_IR_forge.so`.
Let's try running `make all` to check the output:
```sh
Running apprentice_of_the_IR_forge
---------------------------------
mkdir -p bin
clang -O1 -emit-llvm -S src/valid_pass.c -o bin/emit.ll
clang -O1 -fpass-plugin=bin/apprentice_of_the_IR_forge.so src/valid_pass.c -o bin/valid_pass
[-] Nope
```
At first glance, something went wrong. Let's check the `src/valid_pass.c` file:
```c
int main(void) {
  return 0;
}
```
The file content seems pretty empty. What about `bin/apprentice_of_the_IR_forge.so`?
```bash
$ file bin/apprentice_of_the_IR_forge.so
bin/apprentice_of_the_IR_forge.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=51b22af72c486d0d5b61c0b34b77a6633144336c, not stripped
```
So we have our custom LLVM plugin/pass. We can check the exported symbols:
```sh
$ nm bin/apprentice_of_the_IR_forge.so
...
0000000000019948 d __TMC_END__
                 U _Unwind_Resume@GCC_3.0
000000000000e360 T _Z20get_pass_plugin_infov
                 U _ZdlPvm
0000000000019978 V _ZGVZN4llvm11getTypeNameIN4hero11custom_passEEENS_9StringRefEvE4Name
0000000000019960 V _ZGVZN4llvm11getTypeNameINS_27ModuleToFunctionPassAdaptorEEENS_9StringRefEvE4Name
0000000000011890 W _ZN4hero11custom_pass3runERN4llvm8FunctionERNS1_15AnalysisManagerIS2_JEEE
...
```
If we look closely, we can see the "hero" string in the mangled names. Let's filter only on the "hero" string:
```sh
$ nm bin/apprentice_of_the_IR_forge.so | grep hero
0000000000019978 V _ZGVZN4llvm11getTypeNameIN4hero11custom_passEEENS_9StringRefEvE4Name
0000000000011890 W _ZN4hero11custom_pass3runERN4llvm8FunctionERNS1_15AnalysisManagerIS2_JEEE
0000000000013510 W _ZN4llvm11getTypeNameIN4hero11custom_passEEENS_9StringRefEv
0000000000013380 W _ZN4llvm13PassInfoMixinIN4hero11custom_passEE13printPipelineERNS_11raw_ostreamENS_12function_refIFNS_9StringRefES7_EEE
0000000000013410 W _ZN4llvm13PassInfoMixinIN4hero11custom_passEE4nameEv
000000000000f730 W _ZN4llvm33createModuleToFunctionPassAdaptorIN4hero11custom_passEEENS_27ModuleToFunctionPassAdaptorEOT_b
0000000000013600 W _ZN4llvm6detail15getTypeNameImplIN4hero11custom_passEEENS_9StringRefEv
00000000000117b0 W _ZN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEE13printPipelineERNS_11raw_ostreamENS_12function_refIFNS_9StringRefESB_EEE
00000000000137c0 W _ZN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEE18passIsRequiredImplIS4_EENSt9enable_ifIXntsr11is_detectedINS7_14has_required_tET_EE5valueEbE4typeEv
0000000000011770 W _ZN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEE3runERS2_RS6_
00000000000115f0 W _ZN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEEC2ES4_
0000000000011740 W _ZN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEED0Ev
0000000000011720 W _ZN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEED2Ev
0000000000011850 W _ZNK4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEE10isRequiredEv
0000000000011820 W _ZNK4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEE4nameEv
0000000000018d38 V _ZTIN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEEE
0000000000014952 V _ZTSN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEEE
0000000000018cf8 V _ZTVN4llvm6detail9PassModelINS_8FunctionEN4hero11custom_passENS_15AnalysisManagerIS2_JEEEJEEE
0000000000019968 V _ZZN4llvm11getTypeNameIN4hero11custom_passEEENS_9StringRefEvE4Name
```
We can then open this library with our favorite disassembler and check those symbols.

After some analysis, we find that the interesting part is located in `_ZN4hero11custom_pass3runERN4llvm8FunctionERNS1_15AnalysisManagerIS2_JEEE`, or when demangled: `llvm::PreservedAnalyses *__fastcall hero::custom_pass::run(llvm::PreservedAnalyses *a1, __int64 a2, llvm::Value *a3)`. We don't exactly know what arguments this function takes, but if we cross-reference the function twice, we have:
```c
# first cross ref
llvm::PreservedAnalyses *__fastcall hero::custom_pass::run(llvm::PreservedAnalyses *a1, __int64 a2, llvm::Value *a3);

# last cross ref
llvm::PreservedAnalyses *__fastcall llvm::detail::PassModel<llvm::Function,hero::custom_pass,llvm::AnalysisManager<llvm::Function>>::run(
        llvm::PreservedAnalyses *a1,
        __int64 a2,
        llvm::Value *a3);
```
We can see that our pass is a `FunctionPass`, which probably means that the custom pass will parse the IR code at the function level.
Knowing this, we can begin to reverse engineer the custom pass function.
The code is relatively simple. To get the flag, we need to pass this condition:
```c
if ( v22 && (v21 & 1) != 0 && (v20 & 1) != 0 )
  {
    std::ifstream::basic_ifstream(v29, "flag.txt", 8LL);
    if ( (std::ifstream::is_open(v29) & 1) != 0 )
    {
      ...
      v10 = llvm::raw_ostream::operator<<(v11, "[+] Good job here is your flag: ");
      ...
    }
    else
    {
      ...
      llvm::raw_ostream::operator<<(v13, "[-] Call an admin it shouldn't be the case \n");
    }
    ...
  }
  else
  {
    ...
    llvm::raw_ostream::operator<<(v7, "[-] Nope\n");
  }
```
This means that if the v22, v21, and v20 booleans are all true, we will get the flag.
Let's see how we can achieve that. For the first one, the code is:
```c
  llvm::StringRef::StringRef((llvm::StringRef *)v25, "SWORD_OF_THE_HERO");
  Name = llvm::Value::getName(a3);

  v22 = (llvm::operator==(v25[0], v25[1], Name, v3) & 1) != 0;
```
The `a3` variable must represent the `llvm::Function` object (other lines of code support this theory). The code above means we compare the name of the function with the string **"SWORD_OF_THE_HERO"**. This sets the v22 boolean.

Next, for the **v21** boolean, we have the following lines of code:
```c
  v24[0] = llvm::Function::args(a3);
  ...
  v17 = (llvm::Value *)llvm::iterator_range<llvm::Argument *>::begin(v24);
  v16 = llvm::iterator_range<llvm::Argument *>::end(v24);
  while ( v17 != (llvm::Value *)v16 )
  {
    Type = (llvm::Type *)llvm::Value::getType(v17);
    if ( (unsigned int)llvm::Type::getTypeID(Type) == 12 )
      ++v18;
    v17 = (llvm::Value *)((char *)v17 + 40);
  }
  if ( v18 == 3 )
    v21 = 1;
```

If we check the LLVM header file (Type.h), we can see that the type being checked is `llvm::Type::IntegerTyID`. This means the code iterates over all function arguments, and if the current argument is of type IntegerTyID, it increments `v18`. Finally, if `v18` equals 3, our boolean is set to true.

For the last boolean **v20**, the code is as follows:
```c
  ReturnType = (llvm::Type *)llvm::Function::getReturnType(a3);
  if ( (unsigned int)llvm::Type::getTypeID(ReturnType) == 14 )
    v20 = 1;
```
It checks if the return type of the function is `PointerTyID`. If it is, then v20 is set to true.

If we summarize everything, this gives us a function like:
```c
int* SWORD_OF_THE_HERO(uint64_t aaaa, uint64_t bbbb, uint64_t cccc) {
  return 0;
}
```
Let's add this code to our `valid_pass.c` to check if it works:
```sh
Running apprentice_of_the_IR_forge
---------------------------------
mkdir -p bin
clang -O1 -emit-llvm -S src/valid_pass.c -o bin/emit.ll
clang -O1 -fpass-plugin=bin/apprentice_of_the_IR_forge.so src/valid_pass.c -o bin/valid_pass
[+] Good job here is your flag: Hero{FAKE_FLAG}

[-] Nope
```
Yes, it worked! Let's submit this code to the server to get the flag.
The `[-] Nope` string is printed because the main function doesn't validate the pass, which runs on each function in the IR.


### Flag

Hero{Yu0_f0rG3d_y0uR_oWn_p47H_4pPr3nT1cE}
