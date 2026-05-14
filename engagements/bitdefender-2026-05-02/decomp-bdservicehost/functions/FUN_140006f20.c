undefined8 * FUN_140006f20(undefined8 *param_1,uint param_2)

{
  code *pcVar1;
  undefined8 *puVar2;
  
  if (7 < (ulonglong)param_1[7]) {
    if ((0xfff < param_1[7] * 2 + 2U) && (0x1f < (param_1[4] - *(longlong *)(param_1[4] + -8)) - 8U)
       ) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      puVar2 = (undefined8 *)(*pcVar1)();
      return puVar2;
    }
    FUN_14002f180();
  }
  param_1[7] = 7;
  param_1[6] = 0;
  *(undefined2 *)(param_1 + 4) = 0;
  if ((HMODULE)param_1[1] != (HMODULE)0x0) {
    FreeLibrary((HMODULE)param_1[1]);
  }
  *param_1 = bd::framework::details::iplugin_releaser::vftable;
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140006fc0 @ 140006fc0