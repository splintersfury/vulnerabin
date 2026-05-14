undefined8 * FUN_140002c10(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  code *pcVar1;
  undefined8 uVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  longlong local_48 [2];
  undefined8 local_38;
  ulonglong local_30;
  undefined8 *local_28;
  undefined8 uStack_20;
  
  puVar3 = (undefined8 *)*param_3;
  uVar2 = param_3[1];
  local_38 = 0;
  local_30 = 0xf;
  local_48[0] = 0;
  uVar4 = 0xffffffffffffffff;
  do {
    uVar4 = uVar4 + 1;
  } while (*(char *)((longlong)param_2 + uVar4) != '\0');
  local_28 = param_1;
  FUN_1400106a0(local_48,param_2,uVar4);
  local_28 = puVar3;
  uStack_20 = uVar2;
  FUN_140001c20(param_1,&local_28,local_48);
  if (0xf < local_30) {
    if ((0xfff < local_30 + 1) && (0x1f < (local_48[0] - *(longlong *)(local_48[0] + -8)) - 8U)) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      puVar3 = (undefined8 *)(*pcVar1)();
      return puVar3;
    }
    FUN_14002f180();
  }
  *param_1 = std::ios_base::failure::vftable;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002cd0 @ 140002cd0