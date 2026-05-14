void FUN_1400039f0(longlong *param_1)

{
  code *pcVar1;
  
  if (7 < (ulonglong)param_1[0xb]) {
    if ((0xfff < param_1[0xb] * 2 + 2U) &&
       (0x1f < (param_1[8] - *(longlong *)(param_1[8] + -8)) - 8U)) goto LAB_140003af0;
    FUN_14002f180();
  }
  param_1[0xb] = 7;
  param_1[10] = 0;
  *(undefined2 *)(param_1 + 8) = 0;
  if (7 < (ulonglong)param_1[7]) {
    if ((0xfff < param_1[7] * 2 + 2U) && (0x1f < (param_1[4] - *(longlong *)(param_1[4] + -8)) - 8U)
       ) goto LAB_140003af0;
    FUN_14002f180();
  }
  param_1[6] = 0;
  param_1[7] = 7;
  *(undefined2 *)(param_1 + 4) = 0;
  if (7 < (ulonglong)param_1[3]) {
    if ((0xfff < param_1[3] * 2 + 2U) && (0x1f < (*param_1 - *(longlong *)(*param_1 + -8)) - 8U)) {
LAB_140003af0:
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  param_1[2] = 0;
  param_1[3] = 7;
  *(undefined2 *)param_1 = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140003b00 @ 140003b00