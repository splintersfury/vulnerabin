void FUN_1400194a0(undefined8 *param_1,undefined8 param_2,undefined8 *param_3)

{
  ulonglong *puVar1;
  code *pcVar2;
  longlong *plVar3;
  undefined1 auStack_a8 [32];
  undefined1 local_88;
  undefined7 uStack_87;
  undefined8 local_78;
  ulonglong local_70;
  undefined8 ***local_68;
  undefined1 local_60;
  undefined8 local_58;
  ulonglong local_50;
  undefined8 ***local_48;
  longlong lStack_40;
  longlong local_38;
  ulonglong uStack_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_a8;
  local_58 = 0;
  local_50 = 0xf;
  local_68 = (undefined8 ****)0x0;
  FUN_1400106a0((longlong *)&local_68,(undefined8 *)"other_error",0xb);
  plVar3 = FUN_140018380((longlong *)&local_88,&local_68,500);
  puVar1 = param_3 + 2;
  if (0xf < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  plVar3 = FUN_140010800(plVar3,param_3,*puVar1);
  local_48 = (undefined8 ***)*plVar3;
  lStack_40 = plVar3[1];
  local_38 = plVar3[2];
  uStack_30 = plVar3[3];
  plVar3[2] = 0;
  plVar3[3] = 0xf;
  *(undefined1 *)plVar3 = 0;
  if (local_70 < 0x10) {
LAB_14001957d:
    local_78 = 0;
    local_70 = 0xf;
    local_88 = 0;
    if (0xf < local_50) {
      if ((0xfff < local_50 + 1) &&
         (0x1f < (ulonglong)((longlong)local_68 + (-8 - (longlong)local_68[-1]))))
      goto LAB_14001968b;
      FUN_14002f180();
    }
    local_68 = &local_48;
    if (0xf < uStack_30) {
      local_68 = local_48;
    }
    param_1[1] = 0;
    param_1[2] = 0;
    *param_1 = nlohmann::detail::exception::vftable;
    *(undefined4 *)(param_1 + 3) = 500;
    param_1[4] = std::exception::vftable;
    param_1[5] = 0;
    param_1[6] = 0;
    local_60 = 1;
    __std_exception_copy((longlong *)&local_68,param_1 + 5);
    param_1[4] = std::runtime_error::vftable;
    *param_1 = nlohmann::detail::other_error::vftable;
    if (uStack_30 < 0x10) {
LAB_14001965d:
      FUN_14002f160(local_28 ^ (ulonglong)auStack_a8);
      return;
    }
    if ((uStack_30 + 1 < 0x1000) ||
       ((ulonglong)((longlong)local_48 + (-8 - (longlong)local_48[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_14001965d;
    }
    FUN_140035d28();
  }
  else if ((local_70 + 1 < 0x1000) ||
          ((CONCAT71(uStack_87,local_88) - *(longlong *)(CONCAT71(uStack_87,local_88) + -8)) - 8U <
           0x20)) {
    FUN_14002f180();
    goto LAB_14001957d;
  }
  FUN_140035d28();
LAB_14001968b:
  FUN_140035d28();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400196a0 @ 1400196a0