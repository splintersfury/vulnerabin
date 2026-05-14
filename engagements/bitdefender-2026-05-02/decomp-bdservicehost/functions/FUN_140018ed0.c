void FUN_140018ed0(undefined8 *param_1,uint param_2,undefined8 *param_3)

{
  ulonglong *puVar1;
  code *pcVar2;
  longlong *plVar3;
  undefined1 auStack_b8 [32];
  undefined1 local_98;
  undefined7 uStack_97;
  undefined8 local_88;
  ulonglong local_80;
  undefined8 ***local_78;
  undefined1 local_70;
  undefined8 local_68;
  ulonglong local_60;
  undefined8 ***local_58;
  longlong lStack_50;
  longlong local_48;
  ulonglong uStack_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_b8;
  local_68 = 0;
  local_60 = 0xf;
  local_78 = (undefined8 ****)0x0;
  FUN_1400106a0((longlong *)&local_78,(undefined8 *)"invalid_iterator",0x10);
  plVar3 = FUN_140018380((longlong *)&local_98,&local_78,param_2);
  puVar1 = param_3 + 2;
  if (0xf < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  plVar3 = FUN_140010800(plVar3,param_3,*puVar1);
  local_58 = (undefined8 ***)*plVar3;
  lStack_50 = plVar3[1];
  local_48 = plVar3[2];
  uStack_40 = plVar3[3];
  plVar3[2] = 0;
  plVar3[3] = 0xf;
  *(undefined1 *)plVar3 = 0;
  if (local_80 < 0x10) {
LAB_140018fac:
    local_88 = 0;
    local_80 = 0xf;
    local_98 = 0;
    if (0xf < local_60) {
      if ((0xfff < local_60 + 1) &&
         (0x1f < (ulonglong)((longlong)local_78 + (-8 - (longlong)local_78[-1]))))
      goto LAB_1400190b1;
      FUN_14002f180();
    }
    local_78 = &local_58;
    if (0xf < uStack_40) {
      local_78 = local_58;
    }
    param_1[1] = 0;
    param_1[2] = 0;
    *param_1 = nlohmann::detail::exception::vftable;
    *(uint *)(param_1 + 3) = param_2;
    param_1[4] = std::exception::vftable;
    param_1[5] = 0;
    param_1[6] = 0;
    local_70 = 1;
    __std_exception_copy((longlong *)&local_78,param_1 + 5);
    param_1[4] = std::runtime_error::vftable;
    *param_1 = nlohmann::detail::invalid_iterator::vftable;
    if (uStack_40 < 0x10) {
LAB_140019088:
      FUN_14002f160(local_38 ^ (ulonglong)auStack_b8);
      return;
    }
    if ((uStack_40 + 1 < 0x1000) ||
       ((ulonglong)((longlong)local_58 + (-8 - (longlong)local_58[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_140019088;
    }
    FUN_140035d28();
  }
  else if ((local_80 + 1 < 0x1000) ||
          ((CONCAT71(uStack_97,local_98) - *(longlong *)(CONCAT71(uStack_97,local_98) + -8)) - 8U <
           0x20)) {
    FUN_14002f180();
    goto LAB_140018fac;
  }
  FUN_140035d28();
LAB_1400190b1:
  FUN_140035d28();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400190c0 @ 1400190c0