void FUN_140008220(longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  undefined8 *puVar2;
  undefined1 auStack_58 [32];
  longlong *local_38;
  longlong local_30;
  longlong lStack_28;
  longlong local_20;
  ulonglong uStack_18;
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_58;
  local_38 = param_1;
  FUN_140007f90(&local_30,param_2,param_3);
  if (local_20 == 0) {
    *(undefined1 *)(param_1 + 4) = 0;
    if (7 < uStack_18) {
      if ((0xfff < uStack_18 * 2 + 2) && (0x1f < (local_30 - *(longlong *)(local_30 + -8)) - 8U)) {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
  }
  else {
    puVar2 = FUN_14000e630(&local_30,(undefined8 *)&DAT_14006ad08,1);
    FUN_14000e630(puVar2,(undefined8 *)L"bdch.template.json",0x12);
    *param_1 = local_30;
    param_1[1] = lStack_28;
    param_1[2] = local_20;
    param_1[3] = uStack_18;
    *(undefined1 *)(param_1 + 4) = 1;
  }
  FUN_14002f160(local_10 ^ (ulonglong)auStack_58);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008300 @ 140008300

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */