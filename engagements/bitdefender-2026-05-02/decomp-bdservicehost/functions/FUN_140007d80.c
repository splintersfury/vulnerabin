void FUN_140007d80(longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  longlong *plVar2;
  longlong lVar3;
  undefined1 auStack_98 [32];
  ulonglong local_78;
  longlong lStack_70;
  undefined8 local_68;
  ulonglong uStack_60;
  longlong local_58;
  undefined **local_50;
  undefined8 local_48;
  ulonglong local_40;
  longlong local_38;
  longlong lStack_30;
  longlong local_28;
  ulonglong uStack_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_98;
  local_58 = 0;
  local_50 = &PTR_vftable_14007ac70;
  plVar2 = (longlong *)FUN_1400067c0(&local_78,&local_58,param_3);
  local_38 = *plVar2;
  lStack_30 = plVar2[1];
  local_28 = plVar2[2];
  uStack_20 = plVar2[3];
  plVar2[2] = 0;
  plVar2[3] = 7;
  *(undefined2 *)plVar2 = 0;
  if (7 < uStack_60) {
    if ((uStack_60 * 2 + 2 < 0x1000) || ((local_78 - *(longlong *)(local_78 - 8)) - 8 < 0x20)) {
      FUN_14002f180();
      goto LAB_140007e34;
    }
LAB_140007f68:
    FUN_140035d28();
LAB_140007f6e:
    FUN_140035d28();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
LAB_140007e34:
  local_68 = 0;
  uStack_60 = 7;
  local_78 = local_78 & 0xffffffffffff0000;
  if ((uint)local_58 != 0) {
    local_78 = 0;
    local_68 = 0;
    uStack_60 = 7;
    *param_1 = 0;
    param_1[1] = lStack_70;
    param_1[2] = 0;
    param_1[3] = 7;
    *(undefined1 *)(param_1 + 4) = 1;
    if (7 < uStack_20) {
      if ((uStack_20 * 2 + 2 < 0x1000) || ((local_38 - *(longlong *)(local_38 + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_140007f3e;
      }
      goto LAB_140007f6e;
    }
    goto LAB_140007f3e;
  }
  local_48 = 0;
  local_40 = 7;
  local_58 = 0;
  lVar3 = 0xf;
  FUN_140010340(&local_58,(undefined8 *)L"iservconfig.dll",0xf);
  FUN_1400054f0((uint *)&local_38,(uint *)&local_58,lVar3);
  if (7 < local_40) {
    if ((0xfff < local_40 * 2 + 2) && (0x1f < (local_58 - *(longlong *)(local_58 + -8)) - 8U)) {
      FUN_140035d28();
      goto LAB_140007f68;
    }
    FUN_14002f180();
  }
  *param_1 = local_38;
  param_1[1] = lStack_30;
  param_1[2] = local_28;
  param_1[3] = uStack_20;
  *(undefined1 *)(param_1 + 4) = 1;
LAB_140007f3e:
  FUN_14002f160(local_18 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140007f90 @ 140007f90