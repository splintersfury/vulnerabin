void FUN_1400186d0(undefined8 ***param_1,undefined8 param_2,undefined8 *param_3,undefined8 *param_4)

{
  ulonglong *puVar1;
  undefined8 **ppuVar2;
  code *pcVar3;
  undefined8 *puVar4;
  longlong *plVar5;
  char *pcVar6;
  undefined1 auStack_138 [32];
  longlong local_118 [2];
  undefined8 local_108;
  ulonglong local_100;
  undefined1 local_f8;
  undefined7 uStack_f7;
  undefined8 local_e8;
  ulonglong local_e0;
  undefined1 local_d8;
  undefined7 uStack_d7;
  undefined8 local_c8;
  ulonglong local_c0;
  longlong local_b8;
  longlong lStack_b0;
  longlong local_a8;
  ulonglong uStack_a0;
  longlong local_98 [3];
  ulonglong local_80;
  undefined8 ****local_78;
  longlong lStack_70;
  longlong local_68;
  ulonglong uStack_60;
  undefined8 ****local_58;
  longlong lStack_50;
  longlong local_48;
  ulonglong uStack_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_138;
  local_78 = (undefined8 ****)param_1;
  puVar4 = (undefined8 *)FUN_140018aa0(local_98,(longlong)param_3);
  local_108 = 0;
  local_100 = 0xf;
  local_118[0] = 0;
  FUN_1400106a0(local_118,(undefined8 *)"parse_error",0xb);
  plVar5 = FUN_140018380((longlong *)&local_d8,local_118,0x65);
  pcVar6 = "parse error";
  plVar5 = FUN_140010800(plVar5,(undefined8 *)"parse error",0xb);
  local_b8 = *plVar5;
  lStack_b0 = plVar5[1];
  local_a8 = plVar5[2];
  uStack_a0 = plVar5[3];
  plVar5[2] = 0;
  plVar5[3] = 0xf;
  *(undefined1 *)plVar5 = 0;
  FUN_140025910((undefined8 *)&local_f8,pcVar6,&local_b8,puVar4);
  plVar5 = FUN_140010800((longlong *)&local_f8,(undefined8 *)&DAT_14006a930,2);
  local_78 = (undefined8 ****)*plVar5;
  lStack_70 = plVar5[1];
  local_68 = plVar5[2];
  uStack_60 = plVar5[3];
  plVar5[2] = 0;
  plVar5[3] = 0xf;
  *(undefined1 *)plVar5 = 0;
  puVar1 = param_4 + 2;
  if (0xf < (ulonglong)param_4[3]) {
    param_4 = (undefined8 *)*param_4;
  }
  plVar5 = FUN_140010800((longlong *)&local_78,param_4,*puVar1);
  local_58 = (undefined8 ****)*plVar5;
  lStack_50 = plVar5[1];
  local_48 = plVar5[2];
  uStack_40 = plVar5[3];
  plVar5[2] = 0;
  plVar5[3] = 0xf;
  *(undefined1 *)plVar5 = 0;
  if (uStack_60 < 0x10) {
LAB_14001884c:
    local_68 = 0;
    uStack_60 = 0xf;
    local_78 = (undefined8 ****)((ulonglong)local_78 & 0xffffffffffffff00);
    if (0xf < local_e0) {
      if ((local_e0 + 1 < 0x1000) ||
         ((CONCAT71(uStack_f7,local_f8) - *(longlong *)(CONCAT71(uStack_f7,local_f8) + -8)) - 8U <
          0x20)) {
        FUN_14002f180();
        goto LAB_140018899;
      }
      goto LAB_140018a7f;
    }
LAB_140018899:
    local_e8 = 0;
    local_e0 = 0xf;
    local_f8 = 0;
    if (0xf < uStack_a0) {
      if ((uStack_a0 + 1 < 0x1000) || ((local_b8 - *(longlong *)(local_b8 + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_1400188e8;
      }
      goto LAB_140018a85;
    }
LAB_1400188e8:
    if (0xf < local_c0) {
      if ((local_c0 + 1 < 0x1000) ||
         ((CONCAT71(uStack_d7,local_d8) - *(longlong *)(CONCAT71(uStack_d7,local_d8) + -8)) - 8U <
          0x20)) {
        FUN_14002f180();
        goto LAB_140018925;
      }
      goto LAB_140018a8b;
    }
LAB_140018925:
    local_c8 = 0;
    local_c0 = 0xf;
    local_d8 = 0;
    if (local_100 < 0x10) {
LAB_140018976:
      if (0xf < local_80) {
        if ((0xfff < local_80 + 1) && (0x1f < (local_98[0] - *(longlong *)(local_98[0] + -8)) - 8U))
        goto LAB_140018a97;
        FUN_14002f180();
      }
      local_78 = &local_58;
      if (0xf < uStack_40) {
        local_78 = local_58;
      }
      ppuVar2 = (undefined8 **)*param_3;
      param_1[1] = (undefined8 **)0x0;
      param_1[2] = (undefined8 **)0x0;
      *param_1 = (undefined8 **)nlohmann::detail::exception::vftable;
      *(undefined4 *)(param_1 + 3) = 0x65;
      param_1[4] = (undefined8 **)std::exception::vftable;
      param_1[5] = (undefined8 **)0x0;
      param_1[6] = (undefined8 **)0x0;
      lStack_70 = CONCAT71(lStack_70._1_7_,1);
      __std_exception_copy((longlong *)&local_78,(longlong *)(param_1 + 5));
      param_1[4] = (undefined8 **)std::runtime_error::vftable;
      *param_1 = (undefined8 **)nlohmann::detail::parse_error::vftable;
      param_1[7] = ppuVar2;
      if (uStack_40 < 0x10) {
LAB_140018a4d:
        FUN_14002f160(local_38 ^ (ulonglong)auStack_138);
        return;
      }
      if ((uStack_40 + 1 < 0x1000) ||
         ((ulonglong)((longlong)local_58 + (-8 - (longlong)local_58[-1])) < 0x20)) {
        FUN_14002f180();
        goto LAB_140018a4d;
      }
      FUN_140035d28();
      goto LAB_140018a79;
    }
    if ((local_100 + 1 < 0x1000) || ((local_118[0] - *(longlong *)(local_118[0] + -8)) - 8U < 0x20))
    {
      FUN_14002f180();
      goto LAB_140018976;
    }
  }
  else {
    if ((uStack_60 + 1 < 0x1000) ||
       ((ulonglong)((longlong)local_78 + (-8 - (longlong)local_78[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_14001884c;
    }
LAB_140018a79:
    FUN_140035d28();
LAB_140018a7f:
    FUN_140035d28();
LAB_140018a85:
    FUN_140035d28();
LAB_140018a8b:
    FUN_140035d28();
  }
  FUN_140035d28();
LAB_140018a97:
  FUN_140035d28();
  pcVar3 = (code *)swi(3);
  (*pcVar3)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140018aa0 @ 140018aa0