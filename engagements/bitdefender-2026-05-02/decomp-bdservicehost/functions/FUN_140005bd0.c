undefined8 * FUN_140005bd0(undefined8 *param_1,uint param_2)

{
  code *pcVar1;
  undefined8 *puVar2;
  
  if (0xf < (ulonglong)param_1[0x10]) {
    if ((0xfff < param_1[0x10] + 1) &&
       (0x1f < (param_1[0xd] - *(longlong *)(param_1[0xd] + -8)) - 8U)) goto LAB_140005d0c;
    FUN_14002f180();
  }
  param_1[0x10] = 0xf;
  param_1[0xf] = 0;
  *(undefined1 *)(param_1 + 0xd) = 0;
  if (7 < (ulonglong)param_1[0xc]) {
    if ((0xfff < param_1[0xc] * 2 + 2U) &&
       (0x1f < (param_1[9] - *(longlong *)(param_1[9] + -8)) - 8U)) goto LAB_140005d0c;
    FUN_14002f180();
  }
  param_1[0xb] = 0;
  param_1[0xc] = 7;
  *(undefined2 *)(param_1 + 9) = 0;
  if (7 < (ulonglong)param_1[8]) {
    if ((0xfff < param_1[8] * 2 + 2U) && (0x1f < (param_1[5] - *(longlong *)(param_1[5] + -8)) - 8U)
       ) {
LAB_140005d0c:
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      puVar2 = (undefined8 *)(*pcVar1)();
      return puVar2;
    }
    FUN_14002f180();
  }
  param_1[7] = 0;
  param_1[8] = 7;
  *(undefined2 *)(param_1 + 5) = 0;
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140005d20 @ 140005d20