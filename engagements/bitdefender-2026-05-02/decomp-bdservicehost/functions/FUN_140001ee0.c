undefined8 *
FUN_140001ee0(undefined8 *param_1,undefined4 param_2,undefined8 param_3,undefined8 *param_4)

{
  code *pcVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  undefined8 *local_38;
  undefined8 uStack_30;
  longlong local_28 [2];
  undefined8 local_18;
  ulonglong local_10;
  
  local_18 = 0;
  local_10 = 0xf;
  local_28[0] = 0;
  uVar3 = 0xffffffffffffffff;
  do {
    uVar3 = uVar3 + 1;
  } while (*(char *)((longlong)param_4 + uVar3) != '\0');
  local_38 = param_1;
  FUN_1400106a0(local_28,param_4,uVar3);
  local_38 = (undefined8 *)CONCAT44(local_38._4_4_,param_2);
  uStack_30 = param_3;
  FUN_140001c20(param_1,&local_38,local_28);
  if (0xf < local_10) {
    if ((0xfff < local_10 + 1) && (0x1f < (local_28[0] - *(longlong *)(local_28[0] + -8)) - 8U)) {
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

// FUNCTION_START: FUN_140001fc0 @ 140001fc0