void FUN_14000baf0(void)

{
  ulonglong uVar1;
  code *pcVar2;
  int iVar3;
  undefined8 ****ppppuVar4;
  int iVar5;
  ulonglong uVar6;
  undefined8 ***pppuVar7;
  undefined8 *puVar8;
  undefined8 ****ppppuVar9;
  ulonglong uVar10;
  undefined8 ****ppppuVar11;
  ulonglong uVar12;
  undefined1 auStack_108 [32];
  uint local_e8;
  HMODULE *local_e0;
  int local_d8;
  HMODULE *local_d0;
  int local_c8;
  undefined8 ***local_c0;
  undefined8 uStack_b8;
  ulonglong local_b0;
  ulonglong uStack_a8;
  ulonglong local_a0 [2];
  ulonglong local_90;
  ulonglong uStack_88;
  undefined8 ***local_80;
  undefined8 uStack_78;
  ulonglong local_70;
  ulonglong uStack_68;
  undefined8 *local_60;
  undefined8 ***local_58 [2];
  ulonglong local_48;
  ulonglong local_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_108;
  local_e8 = 0;
  iVar5 = SHGetKnownFolderPath(&DAT_14005bb10,0,0xffffffffffffffff,&local_60);
  if (iVar5 < 0) goto LAB_14000bf86;
  local_48 = 0;
  local_40 = 7;
  local_58[0] = (undefined8 ****)0x0;
  uVar12 = 0xffffffffffffffff;
  do {
    uVar12 = uVar12 + 1;
  } while (*(short *)((longlong)local_60 + uVar12 * 2) != 0);
  FUN_140010340((longlong *)local_58,local_60,uVar12);
  CoTaskMemFree(local_60);
  FUN_14000e630(local_58,(undefined8 *)L"\\BDLogging\\",0xb);
  puVar8 = DAT_14007acf0;
  if (7 < (ulonglong)DAT_14007acf0[3]) {
    puVar8 = (undefined8 *)*DAT_14007acf0;
  }
  FUN_14000e630(local_58,puVar8,DAT_14007acf0[2]);
  ppppuVar9 = local_58;
  if (7 < local_40) {
    ppppuVar9 = (undefined8 ****)local_58[0];
  }
  local_90 = 0;
  uStack_88 = 7;
  local_a0[0] = 0;
  FUN_140010340((longlong *)local_a0,ppppuVar9,local_48);
  FUN_14000b620((LPCWSTR)local_a0);
  if (uStack_88 < 8) {
LAB_14000bc3d:
    uVar12 = local_48;
    local_90 = _DAT_14006e180;
    uStack_88 = _UNK_14006e188;
    local_a0[0] = local_a0[0] & 0xffffffffffff0000;
    if (0x7ffffffffffffffe - local_48 < 0xe) goto LAB_14000bfbf;
    ppppuVar9 = local_58;
    if (7 < local_40) {
      ppppuVar9 = (undefined8 ****)local_58[0];
    }
    local_c0 = (undefined8 ****)0x0;
    local_b0 = 0;
    uStack_a8 = 0;
    uVar1 = local_48 + 0xe;
    uVar10 = 7;
    ppppuVar11 = &local_c0;
    ppppuVar4 = (undefined8 ****)local_c0;
    if (7 < uVar1) {
      uVar10 = uVar1 | 7;
      if (uVar10 < 0x7fffffffffffffff) {
        if (uVar10 < 10) {
          uVar10 = 10;
        }
      }
      else {
        uVar10 = 0x7ffffffffffffffe;
      }
      uVar6 = uVar10 + 1;
      if (uVar10 == 0xffffffffffffffff) {
        uVar6 = 0xffffffffffffffff;
      }
      if (0x7fffffffffffffff < uVar6) goto LAB_14000bfd1;
      uVar6 = uVar6 * 2;
      if (uVar6 < 0x1000) {
        ppppuVar11 = (undefined8 ****)0x0;
        ppppuVar4 = (undefined8 ****)0x0;
        if (uVar6 != 0) {
          ppppuVar11 = (undefined8 ****)operator_new(uVar6);
          ppppuVar4 = ppppuVar11;
        }
        goto LAB_14000bd27;
      }
      if (uVar6 + 0x27 <= uVar6) goto LAB_14000bfd1;
      pppuVar7 = (undefined8 ***)operator_new(uVar6 + 0x27);
      if (pppuVar7 != (undefined8 ***)0x0) {
        ppppuVar11 = (undefined8 ****)((longlong)pppuVar7 + 0x27U & 0xffffffffffffffe0);
        ppppuVar11[-1] = pppuVar7;
        ppppuVar4 = ppppuVar11;
        goto LAB_14000bd27;
      }
      FUN_140035d28();
LAB_14000bfcb:
      FUN_140035d28();
LAB_14000bfd1:
      FUN_140001670();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
LAB_14000bd27:
    local_c0 = ppppuVar4;
    uVar12 = uVar12 * 2;
    local_b0 = uVar1;
    uStack_a8 = uVar10;
    FUN_1400316b0(ppppuVar11,ppppuVar9,uVar12);
    *(undefined8 *)((longlong)ppppuVar11 + uVar12) = u__bdservicehost_14006b320._0_8_;
    *(undefined8 *)((wchar_t *)((longlong)ppppuVar11 + uVar12) + 4) =
         u__bdservicehost_14006b320._8_8_;
    *(undefined8 *)((longlong)ppppuVar11 + uVar12 + 0x10) = u__bdservicehost_14006b320._16_8_;
    *(undefined4 *)((longlong)ppppuVar11 + uVar12 + 0x18) = u__bdservicehost_14006b320._24_4_;
    *(undefined2 *)((longlong)ppppuVar11 + uVar1 * 2) = 0;
    local_e8 = 7;
    local_80 = local_c0;
    uStack_78 = uStack_b8;
    local_70 = local_b0;
    uStack_68 = uStack_a8;
    local_b0 = 0;
    uStack_a8 = 7;
    local_c0 = (undefined8 ***)((ulonglong)local_c0 & 0xffffffffffff0000);
    FUN_14000b620((LPCWSTR)&local_80);
    if (7 < uStack_68) {
      if ((0xfff < uStack_68 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_80 + (-8 - (longlong)local_80[-1]))))
      goto LAB_14000bfcb;
      FUN_14002f180();
    }
    local_70 = _DAT_14006e180;
    uStack_68 = _UNK_14006e188;
    local_80 = (undefined8 ***)((ulonglong)local_80 & 0xffffffffffff0000);
    local_b0 = 0;
    uStack_a8 = 7;
    local_c0 = (undefined8 ***)((ulonglong)local_c0 & 0xffffffffffff0000);
    ppppuVar9 = local_58;
    if (7 < local_40) {
      ppppuVar9 = (undefined8 ****)local_58[0];
    }
    if (DAT_14007d500 + DAT_14007d504 == 0) {
      iVar5 = -0x7fffbffb;
    }
    else {
      local_d8 = 0;
      local_e0 = FUN_14000eb20();
      LOCK();
      local_d8 = local_d8 + 1;
      UNLOCK();
      local_e8 = 0xf;
      if (local_e0 == (HMODULE *)0x0) {
        local_e0 = FUN_14000eb20();
        LOCK();
        local_d8 = local_d8 + 1;
        UNLOCK();
      }
      if ((*local_e0 == (HMODULE)0x0) || (local_e0[5] == (HMODULE)0x0)) {
        iVar5 = -0x7fffbffe;
      }
      else {
        iVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)(ppppuVar9);
      }
    }
    if ((local_e8 & 8) != 0) {
      local_e8 = local_e8 & 0xfffffff7;
      local_e0 = (HMODULE *)0x0;
      LOCK();
      UNLOCK();
      iVar3 = local_d8;
      while (local_d8 = iVar3 + -1, -1 < iVar3 + -1) {
        FUN_140011e70();
        LOCK();
        UNLOCK();
        iVar3 = local_d8;
      }
      LOCK();
      UNLOCK();
      local_d8 = iVar3;
    }
    if (-1 < iVar5) {
      if (DAT_14007d500 + DAT_14007d504 != 0) {
        local_c8 = 0;
        local_d0 = FUN_14000eb20();
        LOCK();
        local_c8 = local_c8 + 1;
        UNLOCK();
        local_e8 = local_e8 | 0x10;
        if (local_d0 == (HMODULE *)0x0) {
          local_d0 = FUN_14000eb20();
          LOCK();
          local_c8 = local_c8 + 1;
          UNLOCK();
        }
        if ((*local_d0 != (HMODULE)0x0) && (local_d0[1] != (HMODULE)0x0)) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
      }
      if ((local_e8 & 0x10) != 0) {
        local_e8 = local_e8 & 0xffffffef;
        local_d0 = (HMODULE *)0x0;
        LOCK();
        UNLOCK();
        iVar5 = local_c8;
        while (local_c8 = iVar5 + -1, -1 < iVar5 + -1) {
          FUN_140011e70();
          LOCK();
          UNLOCK();
          iVar5 = local_c8;
        }
        LOCK();
        UNLOCK();
        local_c8 = iVar5;
      }
    }
    if (local_40 < 8) {
LAB_14000bf86:
      FUN_14002f160(local_38 ^ (ulonglong)auStack_108);
      return;
    }
    if ((local_40 * 2 + 2 < 0x1000) ||
       ((ulonglong)((longlong)local_58[0] + (-8 - (longlong)local_58[0][-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_14000bf86;
    }
    FUN_140035d28();
  }
  else if ((uStack_88 * 2 + 2 < 0x1000) ||
          ((local_a0[0] - *(longlong *)(local_a0[0] - 8)) - 8 < 0x20)) {
    FUN_14002f180();
    goto LAB_14000bc3d;
  }
  FUN_140035d28();
LAB_14000bfbf:
  FUN_140001a20();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000bfe0 @ 14000bfe0