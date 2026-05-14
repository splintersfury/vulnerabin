void FUN_140009ba0(longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  undefined1 auStack_68 [32];
  undefined8 local_48;
  undefined **local_40;
  longlong local_38;
  longlong lStack_30;
  longlong local_28;
  ulonglong uStack_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_68;
  local_48 = 0;
  local_40 = &PTR_vftable_14007ac70;
  FUN_1400067c0(&local_38,&local_48,param_3);
  if ((local_40[1] == DAT_14007ac78) && ((int)local_48 == 0)) {
    *param_1 = local_38;
    param_1[1] = lStack_30;
    param_1[2] = local_28;
    param_1[3] = uStack_20;
    *(undefined1 *)(param_1 + 4) = 1;
  }
  else {
    *(undefined1 *)(param_1 + 4) = 0;
    if (7 < uStack_20) {
      if ((0xfff < uStack_20 * 2 + 2) && (0x1f < (local_38 - *(longlong *)(local_38 + -8)) - 8U)) {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_68);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140009c70 @ 140009c70

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */