# The Maze of the Sorcerer

### Category

Reverse

### Difficulty

Medium

### Author

Teddysbears

### Description

Having proven your mettle, you’re summoned by the Archsorcerer of the IR kingdom to a labyrinth woven from loops and branches — a Maze of Tricks. Each room represents a basic block, every decision is a conditional branch.
Only by mastering IR shaping will you be able to escape.

Note: The given archive contains a python script to send your payload to server.
Note: A Dockerfile is also in the archive in order to run the challenge as it is on the server.

TCP: `nc reverse.heroctf.fr 7001`

### Files

- [maze.zip](maze.zip)

### Write Up

This is the second challenge of the triptych. This time we will skip some of the details from the previous challenge (we will also really talk about the IR this time).

This time we have the `maze.zip` archive. We get the following files:
```sh
Archive:  maze.zip
   creating: maze/
  inflating: maze/Makefile
 extracting: maze/flag.txt
   creating: maze/bin/
  inflating: maze/bin/the_maze_of_the_sorcerer.so
   creating: maze/src/
  inflating: maze/src/valid_pass.c
```
We have the exact same directory tree. A quick check on the Makefile shows it also looks similar. Now let's look at `valid_pass.c`.
```c
...
void __attribute__((noinline)) chose_direction(MOVE *moves, uint8_t *cur_move_id, pos_t *initial_pos, pos_t wanted_pos) {
  // TODO
}
...
void __attribute__((noinline)) get_direction(MOVE *moves, uint8_t *cur_move_id, pos_t hero_pos, pos_t exit_pos, pos_t rune_pos) {
  pos_t new_pos = hero_pos;
  pos_t wanted_pos = rune_pos;
  // TODO


  return;
}
...
int main() {
  ...
  memset(g_map, 'M', MAX_X * MAX_Y);

  place_entity(&hero_pos, 'H', all_used_position, &nb_used_position);
  // TODO
  show_map();
...
}
```
As we can see, there is much more code than in the previous challenge. Here we extracted only the parts that include a `// TODO`. To summarize the code quickly: it solves a random maze generated at runtime. Since code is missing for now, it does nothing. But if it's like the previous challenge, we will never run the produced binary.

Now let's open the library.
This time our custom pass looks like:
```
# first ref
llvm::PreservedAnalyses *__fastcall hero::custom_pass::run(llvm::PreservedAnalyses *a1, __int64 a2, llvm::Module *a3)

# second ref
llvm::PreservedAnalyses *__fastcall llvm::detail::PassModel<llvm::Module,hero::custom_pass,llvm::AnalysisManager<llvm::Module>>::run(
        llvm::PreservedAnalyses *a1,
        __int64 a2,
        llvm::Module *a3)
```
This time the pass will not be on a Function but on a Module.
Examining the custom pass code, we also see that 3 booleans have to be true to print the flag.
```c++
if ( (v19 & 1) != 0 && v18 && (v17 & 1) != 0 ) {
  ...
        v8 = llvm::raw_ostream::operator<<(v9, "[+] Good job here is your flag: ");
  ...
}
```
So we need to find a way to set them all to true.
The following code is responsible for the boolean switches: 
```c++
    v19 = hero::first_step((__int64)v31, (__int64)v30) & 1;
    if ( v19 )
    {
      v13 = llvm::outs((llvm *)v31);
      llvm::raw_ostream::operator<<(v13, "[+] First step succeeded\n");
    }
    v18 = hero::second_step((__int64)v30);
    if ( v18 )
    {
      v12 = llvm::outs((llvm *)v30);
      llvm::raw_ostream::operator<<(v12, "[+] Second step succeeded\n");
    }
    v4 = (llvm *)v31;
    v17 = hero::third_step((__int64)v31) & 1;
    if ( v17 )
    {
      v4 = (llvm *)llvm::outs((llvm *)v31);
      llvm::raw_ostream::operator<<(v4, "[+] Third step succeeded\n");
    }
```
We should check those three functions, but first let's check the value of **v31** and **v30** because they are used in all the steps. The first variable is a vector of *CustomFunction*. We don't really know what it is for now, but it is filled with three *llvm::Function* objects. 
```c++
...
      llvm::StringRef::StringRef((llvm::StringRef *)v25, "chose_direction");
      if ( (llvm::operator==(v26, *((_QWORD *)&v26 + 1), v25[0], v25[1]) & 1) != 0
        || (v24 = v27,
            llvm::StringRef::StringRef((llvm::StringRef *)v23, "get_direction"),
            (llvm::operator==(v24, *((_QWORD *)&v24 + 1), v23[0], v23[1]) & 1) != 0)
        || (v22 = v27,
            llvm::StringRef::StringRef((llvm::StringRef *)v21, "main"),
            (llvm::operator==(v22, *((_QWORD *)&v22 + 1), v21[0], v21[1]) & 1) != 0) )
      {
        std::vector<hero::CustomFunction>::emplace_back<llvm::Function &>(v31, v16);
      }
...
```
For **v30**, we only know for now that it's a vector of *llvm::Instruction*.
It's time to dive into the real logic of the challenge.
___
**hero::first_step**

This function seems to be doing many things, but this is due to the verbosity of IDA's C++ decompiler.
The following block makes some checks on the LLVM IR each time. In order to make the function return *true*, we need to pass all these checks without going to `LABEL_25`: `return 0;`. So we need to check how those functions work. 
```c++
  std::vector<llvm::Instruction *>::vector(v22);
  v2 = std::vector<hero::CustomFunction>::operator[](a1, 2LL);
  if ( (hero::CustomFunction::is_other_instruction_in_block(v2, 0LL, v22, 1LL) & 1) == 0 )
    goto LABEL_25;
  v3 = std::vector<hero::CustomFunction>::operator[](a1, 2LL);
  if ( (hero::CustomFunction::is_block_fence_like(v3, 0LL, (__int64)v22, 1) & 1) == 0 )
    goto LABEL_25;
  v4 = (hero::CustomFunction *)std::vector<hero::CustomFunction>::operator[](a1, 2LL);
  if ( !hero::CustomFunction::is_opcode_in_block(v4, 0LL, 35, (__int64)v22, 0) )
    goto LABEL_25;
  v5 = (hero::CustomFunction *)std::vector<hero::CustomFunction>::operator[](a1, 2LL);
  if ( !hero::CustomFunction::is_opcode_in_block(v5, 0LL, 52, (__int64)v22, 0) )
    goto LABEL_25;
  v6 = std::vector<hero::CustomFunction>::operator[](a1, 1LL);
  if ( (hero::CustomFunction::is_block_fence_like(v6, 0LL, a2, 1) & 1) == 0 )
    goto LABEL_25;
  v7 = (hero::CustomFunction *)std::vector<hero::CustomFunction>::operator[](a1, 1LL);
  if ( !hero::CustomFunction::is_opcode_in_block(v7, 0LL, 9, a2, 0) )
    goto LABEL_25;
  v8 = (hero::CustomFunction *)std::vector<hero::CustomFunction>::operator[](a1, 1LL);
  if ( !hero::CustomFunction::is_opcode_in_block(v8, 0LL, 5, a2, 0) || (hero::opcodes_subset(a2, v22) & 1) == 0 )
    goto LABEL_25;
```
If we dive a bit into two of these functions, we can easily guess that those functions are generated from templating. The code below represents the predicate given to `filter_instructions_in_block`. In our case, it's the instruction of type **Fence**.

```c++
char __fastcall hero::CustomFunction::is_block_fence_like(unsigned long,std::vector<llvm::Instruction *> &,bool)::{lambda(llvm::Instruction *)#1}::operator()(
        __int64 a1,
        llvm::Instruction *a2)
{
  return llvm::Instruction::isFenceLike(a2) & 1;
}
``` 
It could also be like (predicate for `is_opcode_in_block`):
```c++
bool __fastcall hero::CustomFunction::is_opcode_in_block(unsigned long,unsigned int,std::vector<llvm::Instruction *> &,bool)::{lambda(llvm::Instruction *)#1}::operator()(
        _DWORD **a1,
        llvm::Instruction *a2)
{
  return (unsigned int)llvm::Instruction::getOpcode(a2) == **a1; // --> need one more argument
}
```
The code of this function is the following(*llvm/IR/Instruction.h*), the instruction could be of 5 types in order to return *true*.
```c++
  bool isFenceLike() const {
    switch (getOpcode()) {
    default:
      return false;
    // This list should be kept in sync with the list in mayWriteToMemory for
    // all opcodes which don't have a memory location.
    case Instruction::Fence:
    case Instruction::CatchPad:
    case Instruction::CatchRet:
    case Instruction::Call:
    case Instruction::Invoke:
      return true;
    }
  }
```
After some reverse engineering, we see the function `filter_instructions_in_block` takes 4 arguments and the object itself. The object is chosen from the previously seen vector of *CustomFunction*: `v3 = std::vector<hero::CustomFunction>::operator[](a1, 2LL);`. This line means it will use the second function, in our case the `main` function. The real first argument is the block index of the IR current function, in most cases *0*. Next it diverges for the `is_opcode_in_block` or `is_block_fence_like` type. The first one takes one more argument which represents the *opcode*. The next argument is the same: it's an array of *llvm::Instruction** from which we keep or remove elements depending on the fourth-fifth argument. When the last argument is true, it will keep the elements that match the predicate; otherwise it will remove them. 
```c++
bool __fastcall hero::CustomFunction::filter_instructions_in_block(
        hero::CustomFunction *a1,
        unsigned __int64 a2,
        __int64 a3,
        __int64 a4, // --> predicate
        char a5)
{
  ...
  v21 = a5 & 1;
  ...
    if ( (std::vector<llvm::Instruction *>::empty(a3) & 1) != 0 )
    {
      while ( (llvm::operator!=(&v24, &v22) & 1) != 0 )
      {
        v14 = llvm::ilist_iterator_w_bits<llvm::ilist_detail::node_options<llvm::Instruction,false,false,void,true,llvm::BasicBlock>,false,false>::operator*(&v24);
        v13 = std::function<bool ()(llvm::Instruction *)>::operator()(a4, v14) & 1;
        if ( (v21 & 1) != 0 && (v13 & 1) != 0 || (v21 & 1) == 0 && (v13 & 1) == 0 )
        {
          std::vector<llvm::Instruction *>::push_back(a3, v20); // --> add the instruction if the predicate is true
        }
        ...
      }
    }
    else
    {
      ...
      v19 = std::remove_if<__gnu_cxx::__normal_iterator<llvm::Instruction **,std::vector<llvm::Instruction *>>,hero::CustomFunction::filter_instructions_in_block(unsigned long,std::vector<llvm::Instruction *>&,std::function<bool ()(llvm::Instruction *)>,bool)::{lambda(llvm::Instruction *)#1}>(
              v12,
              v11,
              a4,
              &v21); // only remove the element: if predicate false and keep matches true or if predicate true and keep matches false.
      v18 = std::vector<llvm::Instruction *>::end(a3);
      std::vector<llvm::Instruction *>::erase(a3, v19, v18);
    }
    return (std::vector<llvm::Instruction *>::empty(a3) & 1) == 0;
  ...
```
So to summarize, if we know the predicate and the parameters, we can write those conditions into simple equations.
Let's go back through each previous line of step_1.
```c++
  std::vector<llvm::Instruction *>::vector(v22);
// main should be at least one instruction of type OtherInstruction (many result)
  if ( (hero::CustomFunction::is_other_instruction_in_block(v2, 0LL, v22, 1LL) & 1) == 0 )
// main from v22 should be at least one instruction of type FenceLike (only possible intersection CALL) 
  if ( (hero::CustomFunction::is_block_fence_like(v3, 0LL, (__int64)v22, 1) & 1) == 0 )
// main from v22 remove all Fence type 
  if ( !hero::CustomFunction::is_opcode_in_block(v4, 0LL, 35, (__int64)v22, 0) )
// main from v22 remove all CatchPad type (CALL still)
  if ( !hero::CustomFunction::is_opcode_in_block(v5, 0LL, 52, (__int64)v22, 0) )
// get_direction from a2 empty instruction of type FenceLike
  if ( (hero::CustomFunction::is_block_fence_like(v6, 0LL, a2, 1) & 1) == 0 )
// get_direction from a2 remove all Invoke 
  if ( !hero::CustomFunction::is_opcode_in_block(v7, 0LL, 9, a2, 0) )
// get_direction from a2 remove all CatchRet 
  if ( !hero::CustomFunction::is_opcode_in_block(v8, 0LL, 5, a2, 0) 
// Check if a2 is a subset of v22 == a2 should at least have a CallInst
  || (hero::opcodes_subset(a2, v22) & 1) == 0 )
```
So the `main` and `get_direction` functions must have at least one call instruction.
Next, we have the following code from `first_step`.
```c++
...
  v21 = (llvm::User **)std::vector<llvm::Instruction *>::begin(v22);
  v20 = std::vector<llvm::Instruction *>::end(v22);
  while ( v21 != (llvm::User **)v20 )
  {
    v17 = *v21;
    v16 = (llvm::CallBase *)llvm::dyn_cast<llvm::CallInst,llvm::Instruction>(*v21);
    if ( !v16 )
      goto LABEL_25;
    CalledFunction = (llvm::Value *)llvm::CallBase::getCalledFunction(v16);
    if ( CalledFunction )
    {
      llvm::StringRef::StringRef((llvm::StringRef *)v19, "place_entity");
      Name = llvm::Value::getName(CalledFunction);
      if ( (llvm::operator!=(v19[0], v19[1], Name, v10) & 1) == 0 )
      {
        Operand = llvm::User::getOperand(v17, 1u);
        v13 = (llvm::Constant *)llvm::dyn_cast<llvm::Constant,llvm::Value>(Operand);
        if ( v13 )
        {
          UniqueInteger = (llvm::APInt *)llvm::Constant::getUniqueInteger(v13);
          switch ( (unsigned int)llvm::APInt::getZExtValue(UniqueInteger) )
          {
            case 'E':
              ++v24;
              break;
            case 'H':
              ++v23;
              break;
            case 'O':
              ++v26;
              break;
            case 'R':
              ++v25;
              break;
            default:
              break;
          }
        }
      }
    }
    ++v21;
  }
  if ( ((v23 != v24) != v25) != v26 )
    v18 = 1;
  ...
```
It is parsing the previously created `v22` (vector of llvm::Instruction). We have confirmation with this line `(llvm::CallBase *)llvm::dyn_cast<llvm::CallInst,llvm::Instruction>(*v21);` that the final instructions are CallInst. Next, it gets an llvm::Function from it and checks if the name is `place_entity`. If it's the case, then it gets the second argument, checks if it's a constant, converts it to an integer value, and finally checks if it's **'H'**, **'E'**, **'R'**, or **'O'**, and increments variables according to the case. If all variables are equal, then we return **true**.
So we have to create 3 other calls in order to validate this one. We will copy the first line above the TODO. We also have to add a call inside the `get_direction` function in order to validate the `first_step`.
```c
void __attribute__((noinline)) get_direction(MOVE *moves, uint8_t *cur_move_id, pos_t hero_pos, pos_t exit_pos, pos_t rune_pos) {
  ...
  puts("toto");
  ...
}
  int main() {
    ...
    place_entity(&hero_pos, 'H', all_used_position, &nb_used_position);
    place_entity(&exit_pos, 'E', all_used_position, &nb_used_position);
    place_entity(&rune_pos, 'R', all_used_position, &nb_used_position);
    place_entity(&orcs_pos, 'O', all_used_position, &nb_used_position);
    ...
  }
```
Let's run make again to check:
```sh
...
opt -load-pass-plugin bin/the_maze_of_the_sorcerer.so -passes=custom_pass bin/emit.ll -o bin/valid_pass.ll
[+] First step succeeded
[-] Nope
...
```
Nice! This one is done. Let's move to the next step. The second step will be a lot quicker with much less code, and we've already seen code like this. As a reminder, the argument `a1` comes from the previous function's `a2`; in fact, it was filled with Call instructions. So here it checks if there are at least two calls to `chose_direction` inside `get_direction`.  
```c++
  v10 = (_QWORD *)std::vector<llvm::Instruction *>::begin(a1);
  v9 = std::vector<llvm::Instruction *>::end(a1);
  while ( v10 != (_QWORD *)v9 )
  {
    v5 = (llvm::CallBase *)llvm::dyn_cast<llvm::CallInst,llvm::Instruction>(*v10);
    if ( !v5 )
      return 0;
    CalledFunction = (llvm::Value *)llvm::CallBase::getCalledFunction(v5);
    if ( CalledFunction )
    {
      llvm::StringRef::StringRef((llvm::StringRef *)v8, "chose_direction");
      Name = llvm::Value::getName(CalledFunction);
      if ( (llvm::operator!=(v8[0], v8[1], Name, v1) & 1) == 0 )
        ++v6;
    }
    ++v10;
  }
  return v6 == 2;
}
```
We can add those calls inside the function to check if we validate the second step. Also, we need to update the code of `chose_direction` because if we check the IR (which is generated automatically with the Makefile in `bin/emit.ll`), the call was doing nothing, so no IR was generated.
Before: 
```c
void __attribute__((noinline)) chose_direction(MOVE *moves, uint8_t *cur_move_id, pos_t *initial_pos, pos_t wanted_pos) {
  // TODO
  return;
}
void __attribute__((noinline)) get_direction(MOVE *moves, uint8_t *cur_move_id, pos_t hero_pos, pos_t exit_pos, pos_t rune_pos) {
  pos_t new_pos = hero_pos;
  pos_t wanted_pos = rune_pos; 
  chose_direction(moves, cur_move_id, &new_pos, wanted_pos);
  chose_direction(moves, cur_move_id, &new_pos, exit_pos);
  
  return;
}
```
IR result (doing nothing): 
```c
define dso_local void @get_direction(ptr noundef readnone captures(none) %0, ptr noundef readnone captures(none) %1, i16 %2, i16 %3, i16 %4) local_unnamed_addr #0 {
  ret void
}
```
After: 
```c
void __attribute__((noinline)) chose_direction(MOVE *moves, uint8_t *cur_move_id, pos_t *initial_pos, pos_t wanted_pos) {
  // TODO
  puts("lol");
  return;
}
```
IR result (doing the calls):
```c
define dso_local void @get_direction(ptr readnone captures(none) %0, ptr readnone captures(none) %1, i16 %2, i16 %3, i16 %4) local_unnamed_addr #0 {
  tail call void @chose_direction(ptr poison, ptr poison, ptr nonnull poison, i16 poison)
  tail call void @chose_direction(ptr poison, ptr poison, ptr nonnull poison, i16 poison)
  ret void
}
```
So if we compile now we get: 
```sh
...
opt -load-pass-plugin bin/the_maze_of_the_sorcerer.so -passes=custom_pass bin/emit.ll -o bin/valid_pass.ll
[+] First step succeeded
[+] Second step succeeded
[-] Nope
...
```
Second step is valid!
The last step was the most difficult because there was a lot of code, but it's always the same pattern. Also, the last step is multi-step, but this time there's no print to check if we pass the check. Now all the checks are on function 0, which is `chose_direction`. 

The `third_step_0` will check:
- block 1 is a subset of block 2 (must be true)
```c++
hero::CustomFunction::is_block_subset_of(v4, 1uLL, 2uLL)
```
- not empty => all memory instructions from block 1, removing GetElementPtr and Store, all this stored in `a2`
```c++
hero::CustomFunction::is_memory_instruction_in_block(v5, 1LL, a2, 1LL) // get all mem inst
hero::CustomFunction::is_opcode_in_block(v6, 1uLL, 34, a2, 0) // remove GetElementPtr
hero::CustomFunction::is_opcode_in_block(v7, 1uLL, 33, a2, 0) // remove Store
```
- not empty => all memory instructions from block 8, removing everything except Load and Store, all this stored in `a3`
```c
hero::CustomFunction::is_memory_instruction_in_block(v8, 8LL, a3, 1LL) // get all mem
hero::CustomFunction::is_opcode_in_block(v9, 8uLL, 35, a3, 0) // remove Fence
hero::CustomFunction::is_opcode_in_block(v10, 8uLL, 31, a3, 0) // remove Alloca
hero::CustomFunction::is_opcode_in_block(v11, 8uLL, 36, a3, 0) // remove AtomicCmpXchg
hero::CustomFunction::is_opcode_in_block(v12, 8uLL, 37, a3, 0) // remove AtomicRMW
hero::CustomFunction::is_opcode_in_block(v13, 8uLL, 34, a3, 0) // remove GetElementPtr
```
- not empty => all memory instructions from block 11, removing everything except Load and GetElementPtr, all this stored in `a4`
```c
hero::CustomFunction::is_memory_instruction_in_block(v14, 0xBLL, a4, 1LL)// get all mem
hero::CustomFunction::is_opcode_in_block(v15, 0xBuLL, 35, a4, 0) // remove Fence
hero::CustomFunction::is_opcode_in_block(v16, 0xBuLL, 31, a4, 0) // remove Alloca
hero::CustomFunction::is_opcode_in_block(v17, 0xBuLL, 36, a4, 0) // remove AtomicCmpXchg
hero::CustomFunction::is_opcode_in_block(v18, 0xBuLL, 37, a4, 0) // remove AtomicRMW
hero::CustomFunction::is_opcode_in_block(v19, 0xBuLL, 33, a4, 0) // remove Store
```
- is `a2` a subset of `a3`
- is `a2` a subset of `a4`
Those two conditions will be satisfied only if `a2` contains only Load instructions.

Now we should begin to create an IR representation that validates those conditions.
```c
// block_0 ? 
// block_1 Load
// block_2 Load
// block_8 Load and Store
// block_11 Load and GetElementPtr
```
Next we have the following code:
```c++
v12 = *(llvm::Instruction **)std::vector<llvm::Instruction *>::operator[](load);
Opcode = llvm::Instruction::getOpcode(v12)
hero::CustomFunction::is_opcode_in_block(v6, 8LL, Opcode, store)
v5 = llvm::Instruction::getOpcode(v12)
hero::CustomFunction::is_opcode_in_block(v4, 11LL, v5, get_element_ptr) 
```
So here we remove all `load` (`a2`) instructions from `store` (`a3`) and `get_element_ptr` (`a4`).
Next, we have another step:
- is block 3 a subset of block 2
```c++
hero::CustomFunction::is_other_instruction_in_block(v3, 2uLL, a2, 1)
```
- not empty => block 2 gets all OtherInstructions, removing everything except Icmp instructions (there are too many lines to show everything):
```c++
hero::CustomFunction::is_opcode_in_block(v4, 2uLL, 54, a2, 0) // remove Fcmp
```
Let's update our IR representation:
```c 
// block_0 ? 
// block_1 Load
// block_2 Load Icmp
// block_3 Icmp
// block_8 Load and Store
// block_11 Load and GetElementPtr
```
Next step checks:
```c++
hero::CustomFunction::is_commutative_instruction_in_block(v2, 4LL, a2, 1LL)
hero::CustomFunction::is_associative_instruction_in_block(v3, 4LL, a2, 1LL)
hero::CustomFunction::is_nilpotent_instruction_in_block(v4, 4LL, a2, 0LL)
hero::CustomFunction::is_idempotent_instruction_in_block(v5, 4LL, a2, 0LL)
hero::CustomFunction::is_opcode_in_block(v6, 4uLL, 17, a2, 0)
```
- not empty => block 4 gets all commutative instructions
```c++
    ...
    case Add: case FAdd:
    case Mul: case FMul:
    case And: case Or: case Xor:
      return true;
    ...
```
- not empty => block 4 gets all associative instructions from a2
```c++
  ...
   return Opcode == And || Opcode == Or || Opcode == Xor ||
           Opcode == Add || Opcode == Mul;
  ...
```
- not empty => block 4 removes all nilpotent instructions
```c++
    return Opcode == Xor;
```
- not empty => block 4 removes all idempotent instructions
```c++
    return Opcode == And || Opcode == Or;
```
- not empty => block 4 removes Mul

Only the Add instruction remains. 
IR representation: 
```c
// block_0 ? 
// block_1 Load
// block_2 Load Icmp
// block_3 Icmp
// block_4 Add
// block_8 Load and Store
// block_11 Load and GetElementPtr
```
Next step checks:
```c++
hero::CustomFunction::is_block_subset_of(v1, 2uLL, 4uLL)
hero::CustomFunction::is_block_subset_of(v2, 3uLL, 6uLL)
hero::CustomFunction::is_blocks_equivalent(v3, 2uLL, 6uLL)
hero::CustomFunction::is_blocks_equivalent(v4, 6uLL, 9uLL)
hero::CustomFunction::is_blocks_equivalent(v5, 9uLL, 0xCuLL)
hero::CustomFunction::is_blocks_equivalent(v6, 4uLL, 7uLL)
hero::CustomFunction::is_blocks_equivalent(v7, 7uLL, 0xAuLL)
hero::CustomFunction::is_blocks_equivalent(v8, 0xAuLL, 0xDuLL)
hero::CustomFunction::is_blocks_equivalent(v9, 5uLL, 8uLL)
hero::CustomFunction::is_blocks_equivalent(v10, 8uLL, 0xBuLL)
hero::CustomFunction::is_blocks_equivalent(v11, 0xBuLL, 0xFuLL)
```
- block 4 includes block 2
- block 6 includes block 3
- block 2 is equivalent to blocks 6, 9, and 12
- block 4 is equivalent to blocks 7, 10, and 14
- block 5 is equivalent to blocks 8, 11, and 15

IR representation: 
```c
// block_0 ? 
// block_1 Load
// block_2 Load Icmp
// block_3 Icmp
// block_4 Add Load Icmp
// block_5 Load Store GetElementPtr
// block_6 Load Icmp
// block_7 Add Load Icmp
// block_8 Load Store GetElementPtr
// block_9 Load Icmp
// block_10 Add Load Icmp
// block_11 Load Store GetElementPtr
// block_12 Load Icmp
// block_13 Add Load Icmp
// block_14 ? 
// block_15 Load Store GetElementPtr
// block_16 ?
```
The results of all the functions extracting one instruction type will be used in the next checks.
Next step checks:
A new function is called many times: 
```c++
char __fastcall hero::third_step_4(__int64 a1, int a2, unsigned int a3, llvm::Instruction *a4, int a5, unsigned int a6)
```
The first parameter is, as always, the custom_function. There are 4 functions in one; the second parameter defines which type it is. The third argument is the block id. The fourth argument is the kind of instruction checked. The fifth is only used in type 0, representing an instruction type. The sixth argument is a value to check.
First, it checks if the instruction type `a3` is in the selected block, also extracting it into `v14`: 
```c++
hero::CustomFunction::is_opcode_in_block(v7, a3, Opcode, v14, 1LL)
```
The switch case to choose the correct function:
```c++
    switch ( a2 )
    {
      case 0:
        v9 = hero::check_inst_0((__int64)v14, a5) & 1;
        break;
      case 1:
        v9 = hero::check_inst_1(v14, a6) & 1;
        break;
      case 2:
        v9 = hero::check_inst_2(v14, a6) & 1;
        break;
      case 3:
        v9 = hero::check_inst_3(v14) & 1;
        break;
      default:
        break;
    }
```
0) check_inst_0 => the condition must be true; it checks if the predicate of the icmp matches the fifth argument.
```c++
llvm::CmpInst::getPredicate(v3) == a2
```
1) check_inst_1 => the condition must be true; it checks that the second operand of the instruction is a const value equal to the sixth argument.
```c++
Operand = llvm::User::getOperand(*v8, 1u)
v4 = (llvm::Constant *)llvm::dyn_cast<llvm::Constant,llvm::Value>(Operand)
UniqueInteger = (llvm::APInt *)llvm::Constant::getUniqueInteger(v4)
llvm::APInt::getSExtValue(UniqueInteger) == a2
```
2) check_inst_2 => the condition must be true; it checks that the first operand of the instruction is a const value equal to the sixth argument.
```c++
Operand = llvm::User::getOperand(*v8, 0)
v4 = (llvm::Constant *)llvm::dyn_cast<llvm::Constant,llvm::Value>(Operand)
UniqueInteger = (llvm::APInt *)llvm::Constant::getUniqueInteger(v4)
llvm::APInt::getSExtValue(UniqueInteger) == a2
```
3) check_inst_3 => the condition must be true; it checks that the pointer operand of the GetElementPtrInst is a global variable named **"g_map"**.
```c++
v7 = (llvm::GetElementPtrInst *)llvm::dyn_cast<llvm::GetElementPtrInst,llvm::Instruction>(*v11)
PointerOperand = llvm::GetElementPtrInst::getPointerOperand(v7)
v5 = (llvm::Value *)llvm::dyn_cast<llvm::GlobalVariable,llvm::Value>(PointerOperand)
Name = llvm::Value::getName(v5)
llvm::StringRef::StringRef((llvm::StringRef *)v9, "g_map")
```
The calls are the following: 
```c++
// type 0, block 3 (ICMP_UGT), block 6 (ICMP_ULT), block 9 (ICMP_UGT), block 12 (ICMP_ULT)
hero::third_step_4(a1, 0, 3u, v9, 0x22, 0)
hero::third_step_4(a1, 0, 6u, v9, 0x24, 0)
hero::third_step_4(a1, 0, 9u, v9, 0x22, 0)
hero::third_step_4(a1, 0, 12u, v9, 0x24, 0)
// type 1, block 4 (-1), block 7 (1), block 10 (-1), block 14 (1)
hero::third_step_4(a1, 1, 4u, v8, 0, 0xFFFFFFFF)
hero::third_step_4(a1, 1, 7u, v8, 0, 1u)
hero::third_step_4(a1, 1, 0xAu, v8, 0, 0xFFFFFFFF)
hero::third_step_4(a1, 1, 13, v8, 0LL)
// type 2, block 5 (0), block 8 (1), block 11 (2), block 15 (3)
hero::third_step_4(a1, 2, 5u, v10, 0, 0)
hero::third_step_4(a1, 2, 8u, v10, 0, 1u)
hero::third_step_4(a1, 2, 0xBu, v10, 0, 2u)
hero::third_step_4(a1, 2, 0xFu, v10, 0, 3u)
// type 3, block 4, block 7, block 10, block 14 (g_map)
hero::third_step_4(a1, 3, 4u, v11, 0, 0)
hero::third_step_4(a1, 3, 7u, v11, 0, 0)
hero::third_step_4(a1, 3, 0xAu, v11, 0, 0)
hero::third_step_4(a1, 3, 13, v11, 0LL)
```
We can update the IR representation: 
```c
// block_0 ? 
// block_1 Load
// block_2 Load Icmp
// block_3 Icmp_UGT
// block_4 Add_-1 Load Icmp GetElementPtr_g_map
// block_5 Load Store_0 GetElementPtr
// block_6 Load Icmp_ULT
// block_7 Add_1 Load Icmp GetElementPtr_g_map
// block_8 Load Store_1 GetElementPtr
// block_9 Load Icmp_UGT
// block_10 Add_-1 Load Icmp GetElementPtr_g_map
// block_11 Load Store_2 GetElementPtr
// block_12 Load Icmp_ULT
// block_13 Add_1 Load Icmp GetElementPtr_g_map
// block_14 ?
// block_15 Load Store_3 GetElementPtr
// block_16 ?
```
There are two last checks:
```c++
// block 13 must have at least one Branch instruction
hero::CustomFunction::is_opcode_in_block(v1, 14LL, 2LL, v14, 1LL)
// block 16 must have at least one Return instruction
hero::CustomFunction::is_opcode_in_block(v2, 16LL, 1LL, v14, 1LL)
```
One last update to the IR: 
```c
// block_0 ? 
// block_1 Load
// block_2 Load Icmp
// block_3 Icmp_UGT
// block_4 Add_-1 Load Icmp
// block_5 Load Store_0 GetElementPtr_g_map
// block_6 Load Icmp_ULT
// block_7 Add_1 Load Icmp
// block_8 Load Store_1 GetElementPtr_g_map
// block_9 Load Icmp_UGT
// block_10 Add_-1 Load Icmp
// block_11 Load Store_2 GetElementPtr_g_map
// block_12 Load Icmp_ULT
// block_13 Add_1 Load Icmp GetElementPtr_g_mapch 
// block_14 Branch
// block_15 Load Store_3 GetElementPtr_g_map
// block_16 Return
```
From what we know, the function must choose a direction from two given positions, updating moves, cur_move_id, and initial_pos because they are given as pointers.
So we have two choices: try to make a real solution for the maze or just satisfy the checks.
Here we'll try to make it work.

Hypotheses (based on some tests with the generated IR from `emit.ll`):
1) it probably stores `MOVE` type inside `*moves` because we have 4 stores with the four possible values of `MOVE`.
2) the `initial_pos` could be updated with add (1) or add (-1) in order to follow the `moves`
3) the branch must indicate a loop
4) there are no checks on block_0; maybe we can initialize variables in order to validate the conditions
5) the `icmp(_ULT,_UGT)` could check where `initial_pos` is compared to the `wanted_pos` coordinates
6) the `GetElementPtr` on the `g_map` might be a check to see if `initial_pos` tries to go outside the `g_map`, but all the checks happen when the labyrinth is set up. Maybe it's a check for whether there is an `ORC` **"O"** on the updated position.

From those hypotheses, we wrote the following pseudo code: 
```c
void __attribute__((noinline)) chose_direction(MOVE *moves, uint8_t *cur_move_id, pos_t *initial_pos, pos_t wanted_pos) {
  // 4. 
  // 3.
  while(initial_pos != wanted_pos) {
    // repeat this 4 times according to differents checks
    // 5.
    if(initial_pos > || < wanted_pos) {
      // 6.
      if(g_map[futur_pos] != ORCS) {
        // 2.
        initial_pos +1 || -1
        // 1. 
        moves[*cur_move_id] = MOVE::?
        (*cur_move_id)++;
      }
    }
  }
}
```
Let's try to write one step and check the IR:
```c
  while(initial_pos->y != wanted_pos.y || initial_pos->x != wanted_pos.x) {
    // repeat this 4 times according to differents checks
    // 5.
    if(initial_pos->x > wanted_pos.x) {
      // 6.
      if(g_map[initial_pos->x - 1][initial_pos->y] == 'O') {
        // 2.
         initial_pos->x -= 1;
        // 1. 
        moves[*cur_move_id] = RIGHT;
        (*cur_move_id)++;
      }
    }
  }
```
IR result from `emit.ll`:
```s
  %5 = lshr i16 %3, 8
  %6 = getelementptr inbounds nuw i8, ptr %2, i64 1
  %7 = trunc i16 %3 to i8
  %8 = and i16 %3, 255
  br label %9

9:                                                ; preds = %28, %4
  %10 = load i8, ptr %6, align 1, !tbaa !5        ; ---- LOAD HERE
  %11 = zext i8 %10 to i16
  %12 = icmp eq i16 %5, %11
  br i1 %12, label %13, label %16

13:                                               ; preds = %9
  %14 = load i8, ptr %2, align 1, !tbaa !9
  %15 = icmp eq i8 %14, %7
  br i1 %15, label %36, label %16

16:                                               ; preds = %9, %13
  %17 = load i8, ptr %2, align 1, !tbaa !9
  %18 = zext i8 %17 to i16
  %19 = icmp samesign ult i16 %8, %18             ; ---- ICMP ULT HERE (strange, should be UGT)
  br i1 %19, label %20, label %28

20:                                               ; preds = %16
  %21 = zext i8 %17 to i32
  %22 = add nsw i32 %21, -1                       ; ---- ADD -1 HERE
  %23 = zext nneg i32 %22 to i64
  %24 = zext i8 %10 to i64
  %25 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %23, i64 %24 ; ---- GetElementPtr g_map HERE but wrong block?
  %26 = load i8, ptr %25, align 1, !tbaa !10
  %27 = icmp eq i8 %26, 79
  br i1 %27, label %29, label %28

28:                                               ; preds = %20, %29, %16
  br label %9, !llvm.loop !11                     ; ---- Branch HERE

29:                                               ; preds = %20
  %30 = trunc nuw i32 %22 to i8
  store i8 %30, ptr %2, align 1, !tbaa !9
  %31 = load i8, ptr %1, align 1, !tbaa !10
  %32 = zext i8 %31 to i64
  %33 = getelementptr inbounds nuw i32, ptr %0, i64 %32
  store i32 1, ptr %33, align 4, !tbaa !14        ; ---- Store 1 HERE (should be 0)
  %34 = load i8, ptr %1, align 1, !tbaa !10
  %35 = add i8 %34, 1
  store i8 %35, ptr %1, align 1, !tbaa !10
  br label %28

36:                                               ; preds = %13
  ret void                                        ; ---- Return HERE

```
OK, some blocks are wrong, but maybe if we add all the blocks it will work:
```c
  // 3.
  while(initial_pos->x != wanted_pos.x || initial_pos->y != wanted_pos.y)  {
    // repeat this 4 times according to differents checks
    // 5.
    if(initial_pos->x > wanted_pos.x) {
      // 6.
      if(g_map[initial_pos->x - 1][initial_pos->y] != 'O') {
        // 2.
         initial_pos->x -= 1;
        // 1. 
        moves[*cur_move_id] = LEFT;
        (*cur_move_id)++;
      }
    }
    // 5.
    if(initial_pos->x < wanted_pos.x) {
      // 6.
      if(g_map[initial_pos->x + 1][initial_pos->y] != 'O') {
        // 2.
         initial_pos->x += 1;
        // 1. 
        moves[*cur_move_id] = RIGHT;
        (*cur_move_id)++;
      }
    }
    // 5.
    if(initial_pos->y > wanted_pos.y) {
      // 6.
      if(g_map[initial_pos->x][initial_pos->y - 1] != 'O') {
        // 2.
         initial_pos->y -= 1;
        // 1. 
        moves[*cur_move_id] = UP;
        (*cur_move_id)++;
      }
    }
    // 5.
    if(initial_pos->y < wanted_pos.y) {
      // 6.
      if(g_map[initial_pos->x][initial_pos->y + 1] != 'O') {
        // 2.
         initial_pos->y += 1;
        // 1. 
        moves[*cur_move_id] = DOWN;
        (*cur_move_id)++;
      }
    }
  }
```
Let's try to run the makefile to see if it works: 
```sh
...
opt -load-pass-plugin bin/the_maze_of_the_sorcerer.so -passes=custom_pass bin/emit.ll -o bin/valid_pass.ll
[+] First step succeeded
[+] Second step succeeded
[+] Third step succeeded
[+] Good job here is your flag: Hero{FAKE_FLAG}
...
```
**It works**! We just need to send the code to the server and it will give us the flag.

### Flag

Hero{Yu0_f0uNd_tH3_W4Y_oU7_0f_Th3_50rC3Rer_M4z3}
