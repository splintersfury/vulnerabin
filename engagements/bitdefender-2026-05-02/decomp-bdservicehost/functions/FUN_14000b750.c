void FUN_14000b750(void)

{
  code *pcVar1;
  int iVar2;
  uint *puVar3;
  ulonglong uVar4;
  longlong lVar5;
  undefined1 auStack_128 [40];
  ulonglong local_100 [2];
  undefined8 local_f0;
  ulonglong uStack_e8;
  ulonglong local_e0 [2];
  undefined8 local_d0;
  ulonglong uStack_c8;
  undefined8 local_c0 [2];
  undefined8 local_b0;
  ulonglong uStack_a8;
  longlong local_a0 [3];
  ulonglong local_88;
  longlong local_80 [3];
  ulonglong local_68;
  undefined8 *local_60;
  longlong local_58 [2];
  undefined8 local_48;
  ulonglong local_40;
  WCHAR local_38;
  undefined6 uStack_36;
  undefined8 local_28;
  ulonglong uStack_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_128;
  uVar4 = 0xffffffffffffffff;
  iVar2 = SHGetKnownFolderPath(&DAT_14005bb10,0,0xffffffffffffffff,&local_60);
  if (iVar2 < 0) goto LAB_14000ba9e;
  do {
    uVar4 = uVar4 + 1;
  } while (*(short *)((longlong)local_60 + uVar4 * 2) != 0);
  local_48 = 0;
  local_40 = 7;
  local_58[0] = 0;
  FUN_140010340(local_58,local_60,uVar4);
  CoTaskMemFree(local_60);
  local_d0 = 0;
  uStack_c8 = 7;
  local_e0[0] = 0;
  FUN_140010340((longlong *)local_e0,(undefined8 *)L"bdservicehost",0xd);
  local_f0 = 0;
  uStack_e8 = 7;
  local_100[0] = 0;
  lVar5 = 9;
  FUN_140010340((longlong *)local_100,(undefined8 *)L"BDLogging",9);
  FUN_14000e750(local_c0,local_58);
  puVar3 = FUN_1400054f0((uint *)local_c0,(uint *)local_100,lVar5);
  FUN_14000e750(local_80,(undefined8 *)puVar3);
  if (uStack_a8 < 8) {
LAB_14000b89f:
    local_b0 = _DAT_14006e180;
    uStack_a8 = _UNK_14006e188;
    local_c0[0]._0_2_ = 0;
    FUN_14000e750(local_a0,local_80);
    puVar3 = FUN_1400054f0((uint *)local_a0,(uint *)local_e0,lVar5);
    FUN_14000e750((undefined8 *)&local_38,(undefined8 *)puVar3);
    if (7 < local_88) {
      if ((local_88 * 2 + 2 < 0x1000) ||
         ((local_a0[0] - *(longlong *)(local_a0[0] + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_14000b91c;
      }
      goto LAB_14000bacb;
    }
LAB_14000b91c:
    if (7 < local_68) {
      if ((local_68 * 2 + 2 < 0x1000) ||
         ((local_80[0] - *(longlong *)(local_80[0] + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_14000b95d;
      }
      goto LAB_14000bad1;
    }
LAB_14000b95d:
    if (7 < uStack_e8) {
      if ((uStack_e8 * 2 + 2 < 0x1000) ||
         ((local_100[0] - *(longlong *)(local_100[0] - 8)) - 8 < 0x20)) {
        FUN_14002f180();
        goto LAB_14000b99f;
      }
      goto LAB_14000bad7;
    }
LAB_14000b99f:
    local_f0 = _DAT_14006e180;
    uStack_e8 = _UNK_14006e188;
    local_100[0] = local_100[0] & 0xffffffffffff0000;
    if (uStack_c8 < 8) {
LAB_14000b9f4:
      local_d0 = _DAT_14006e180;
      uStack_c8 = _UNK_14006e188;
      local_e0[0] = local_e0[0] & 0xffffffffffff0000;
      FUN_14000b620(&local_38);
      if (7 < uStack_20) {
        if ((0xfff < uStack_20 * 2 + 2) &&
           (0x1f < (CONCAT62(uStack_36,local_38) - *(longlong *)(CONCAT62(uStack_36,local_38) + -8))
                   - 8U)) goto LAB_14000bae3;
        FUN_14002f180();
      }
      local_28 = _DAT_14006e180;
      uStack_20 = _UNK_14006e188;
      local_38 = L'\0';
      if (local_40 < 8) {
LAB_14000ba9e:
        FUN_14002f160(local_18 ^ (ulonglong)auStack_128);
        return;
      }
      if ((local_40 * 2 + 2 < 0x1000) ||
         ((local_58[0] - *(longlong *)(local_58[0] + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_14000ba9e;
      }
      FUN_140035d28();
      goto LAB_14000bac5;
    }
    if ((uStack_c8 * 2 + 2 < 0x1000) || ((local_e0[0] - *(longlong *)(local_e0[0] - 8)) - 8 < 0x20))
    {
      FUN_14002f180();
      goto LAB_14000b9f4;
    }
  }
  else {
    if ((uStack_a8 * 2 + 2 < 0x1000) ||
       ((CONCAT62(local_c0[0]._2_6_,(undefined2)local_c0[0]) -
        *(longlong *)(CONCAT62(local_c0[0]._2_6_,(undefined2)local_c0[0]) + -8)) - 8U < 0x20)) {
      FUN_14002f180();
      goto LAB_14000b89f;
    }
LAB_14000bac5:
    FUN_140035d28();
LAB_14000bacb:
    FUN_140035d28();
LAB_14000bad1:
    FUN_140035d28();
LAB_14000bad7:
    FUN_140035d28();
  }
  FUN_140035d28();
LAB_14000bae3:
  FUN_140035d28();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000baf0 @ 14000baf0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */