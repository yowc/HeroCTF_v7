#pragma once
#include <string>
struct ChallengeState {
  bool stage1 = false;
  bool stage2 = false;
  bool stage3 = false;
  bool stage4 = false;
  bool stage5 = false;

  std::string gv_stage1; 
  std::string gv_stage2; 
  std::string gv_stage3; 
  std::string gv_rv;
  std::string gv_table_size;
  std::string gv_table;
};

static bool check_state(ChallengeState chall_state) {
  return chall_state.stage1 && chall_state.stage2 && chall_state.stage3 && chall_state.stage4 && chall_state.stage5;
}
