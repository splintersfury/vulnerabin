undefined8 *
FUN_140005810(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3,undefined8 *param_4)

{
  code *pcVar1;
  undefined8 *puVar2;
  char *local_58;
  longlong lStack_50;
  longlong local_48 [3];
  ulonglong uStack_30;
  undefined8 *local_28;
  
  local_58 = (char *)*param_4;
  lStack_50 = param_4[1];
  local_28 = param_1;
  FUN_140001c20(param_1,&local_58,param_2);
  *param_1 = std::filesystem::filesystem_error::vftable;
  FUN_14000e750(param_1 + 5,param_3);
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[9] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 7;
  *(undefined2 *)(param_1 + 9) = 0;
  local_48[1] = 0;
  local_48[2] = _DAT_14006e180;
  uStack_30 = _UNK_14006e188;
  local_48[0] = 0;
  local_58 = "Unknown exception";
  if ((char *)param_1[1] != (char *)0x0) {
    local_58 = (char *)param_1[1];
  }
  lStack_50 = -1;
  do {
    lStack_50 = lStack_50 + 1;
  } while (local_58[lStack_50] != '\0');
  FUN_140005940((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                (param_1 + 0xd),&local_58,param_3,local_48);
  if (7 < uStack_30) {
    if ((0xfff < uStack_30 * 2 + 2) && (0x1f < (local_48[0] - *(longlong *)(local_48[0] + -8)) - 8U)
       ) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      puVar2 = (undefined8 *)(*pcVar1)();
      return puVar2;
    }
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140005930 @ 140005930