undefined8 * FUN_140003760(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  code *pcVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  longlong local_38 [2];
  undefined8 local_28;
  ulonglong local_20;
  undefined8 local_18;
  undefined8 uStack_10;
  
  local_38[0] = 0;
  local_28 = 0;
  local_20 = 0xf;
  uVar3 = 0xffffffffffffffff;
  do {
    uVar3 = uVar3 + 1;
  } while (*(char *)((longlong)param_3 + uVar3) != '\0');
  FUN_1400106a0(local_38,param_3,uVar3);
  local_18 = *param_2;
  uStack_10 = param_2[1];
  FUN_140001c20(param_1,&local_18,local_38);
  if (0xf < local_20) {
    if ((0xfff < local_20 + 1) && (0x1f < (local_38[0] - *(longlong *)(local_38[0] + -8)) - 8U)) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      puVar2 = (undefined8 *)(*pcVar1)();
      return puVar2;
    }
    FUN_14002f180();
  }
  *param_1 = std::system_error::vftable;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140003820 @ 140003820