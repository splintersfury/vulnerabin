void __thiscall FUN_1000d450(void *this,int *param_1,undefined **param_2)

{
  char cVar1;
  WCHAR WVar2;
  UINT uID;
  code *pcVar3;
  LPCWSTR **pppWVar4;
  uint uVar5;
  int *piVar6;
  short *psVar7;
  undefined4 *puVar8;
  wchar_t *pwVar9;
  int iVar10;
  uint *puVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  LPCWSTR ***ppppWVar14;
  void *pvVar15;
  undefined **ppuVar16;
  int *extraout_ECX;
  undefined **ppuVar17;
  LPCWSTR **local_1c8;
  void *pvStack_1c4;
  undefined4 uStack_1c0;
  undefined4 uStack_1bc;
  undefined4 local_1b8;
  uint uStack_1b4;
  void *local_1b0;
  undefined4 uStack_1ac;
  undefined4 local_1a0;
  uint uStack_19c;
  undefined4 local_198;
  LPCWSTR **local_194;
  void *pvStack_190;
  undefined4 uStack_18c;
  undefined4 uStack_188;
  undefined8 local_184;
  wchar_t *local_17c;
  char local_175;
  uint local_174 [6];
  CHAR local_15c [24];
  char local_144;
  int local_140 [4];
  int local_130 [2];
  undefined1 local_128 [152];
  void *local_90;
  undefined **ppuStack_8c;
  void *pvStack_88;
  undefined4 uStack_84;
  undefined8 local_78;
  char local_70;
  void *local_6c;
  undefined4 uStack_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined8 local_5c;
  void *local_54;
  undefined **ppuStack_50;
  void *pvStack_4c;
  undefined4 uStack_48;
  uint uStack_40;
  void *local_3c;
  undefined **local_38;
  undefined8 local_34;
  undefined **local_2c;
  int *local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14._0_1_ = 0xff;
  local_14._1_3_ = 0xffffff;
  puStack_18 = &LAB_1004e853;
  local_1c = ExceptionList;
  uVar5 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_2c = (undefined **)0x0;
  local_38 = param_2;
  cVar1 = *(char *)((int)DAT_1006b658[1] + 0xd);
  puVar8 = (undefined4 *)DAT_1006b658[1];
  puVar13 = DAT_1006b658;
  while (puVar12 = puVar8, cVar1 == '\0') {
    if ((int *)puVar12[4] < param_1) {
      puVar8 = (undefined4 *)puVar12[2];
      puVar12 = puVar13;
    }
    else {
      puVar8 = (undefined4 *)*puVar12;
    }
    cVar1 = *(char *)((int)puVar8 + 0xd);
    puVar13 = puVar12;
  }
  if ((*(char *)((int)puVar13 + 0xd) != '\0') || (param_1 < (int *)puVar13[4])) {
    puVar13 = DAT_1006b658;
  }
  local_28 = (int *)this;
  local_24 = uVar5;
  if (puVar13 != DAT_1006b658) {
    uID = puVar13[5];
    ppuVar17 = (undefined **)FUN_1002e6ac(0xfffe);
    _memset(ppuVar17,0,0xfffe);
    local_14._0_1_ = 0x13;
    local_14._1_3_ = 0;
    local_2c = ppuVar17;
    iVar10 = LoadStringW((HINSTANCE)&IMAGE_DOS_HEADER_10000000,uID,(LPWSTR)ppuVar17,0x7fff);
    if (iVar10 == 0) {
      local_175 = '\0';
    }
    else {
      ppuVar16 = ppuVar17;
      do {
        WVar2 = *(WCHAR *)ppuVar16;
        ppuVar16 = (undefined **)((int)ppuVar16 + 2);
      } while (WVar2 != L'\0');
      FUN_10001d40(local_38,(uint *)ppuVar17,(int)ppuVar16 - (int)((int)ppuVar17 + 2) >> 1);
      local_175 = '\x01';
    }
    thunk_FUN_100330ca(ppuVar17);
    goto LAB_1000de25;
  }
  if (param_1 != (int *)0x190) {
    if (param_1 == (int *)0xc9) {
      puStack_20 = &stack0xfffffffc;
      _memset(local_140,0,0xb0);
      FUN_1000dfd0(local_140);
      local_14._0_1_ = 0x10;
      local_14._1_3_ = 0;
      piVar6 = FUN_100082c0(local_130,L"SOFTWARE\\");
      psVar7 = (short *)(**(code **)(*local_28 + 0x28))();
      piVar6 = FUN_100082c0(piVar6,psVar7);
      pwVar9 = L"\\Submission";
    }
    else if (param_1 == (int *)0xca) {
      puStack_20 = &stack0xfffffffc;
      _memset(local_140,0,0xb0);
      FUN_1000dfd0(local_140);
      local_14._0_1_ = 0x11;
      local_14._1_3_ = 0;
      piVar6 = FUN_100082c0(local_130,L"SOFTWARE\\");
      psVar7 = (short *)(**(code **)(*local_28 + 0x28))();
      piVar6 = FUN_100082c0(piVar6,psVar7);
      pwVar9 = L"\\Submission\\Agent Submission Tool";
    }
    else {
      if (param_1 != (int *)0xcd) {
        if (((((int *)0x2be < param_1) && (param_1 < (int *)0x2f6)) ||
            (param_1 == (int *)0xffffffff)) ||
           (puStack_20 = &stack0xfffffffc, param_1 == (int *)0xfffffffe)) {
          local_28 = param_1;
          puStack_20 = &stack0xfffffffc;
          FUN_10001890((int *)&local_34,(uint *)&local_28);
          ppuVar17 = local_2c;
          if (((*(char *)((int)local_2c + 0xd) == '\0') && (local_2c[4] <= param_1)) &&
             (local_2c != DAT_1006b644)) {
            iVar10 = FUN_1001e130();
            FUN_10023ea0((int *)(iVar10 + 0x60),(int *)&local_34,(int *)(ppuVar17 + 5));
            if (((*(char *)((int)local_2c + 0xd) == '\0') && ((int)local_2c[4] <= (int)ppuVar17[5]))
               && (local_2c != *(undefined ***)(iVar10 + 0x60))) {
              ppuVar17 = local_2c + 5;
              if ((undefined *)0x7 < local_2c[10]) {
                ppuVar17 = (undefined **)*ppuVar17;
              }
            }
            else {
              ppuVar17 = (undefined **)&DAT_10060130;
            }
            ppuVar16 = ppuVar17;
            do {
              WVar2 = *(WCHAR *)ppuVar16;
              ppuVar16 = (undefined **)((int)ppuVar16 + 2);
            } while (WVar2 != L'\0');
            FUN_10001d40(local_38,(uint *)ppuVar17,(int)ppuVar16 - (int)((int)ppuVar17 + 2) >> 1);
          }
        }
        goto LAB_1000de25;
      }
      puStack_20 = &stack0xfffffffc;
      _memset(local_140,0,0xb0);
      FUN_1000dfd0(local_140);
      local_14._0_1_ = 0x12;
      local_14._1_3_ = 0;
      piVar6 = FUN_100082c0(local_130,L"SOFTWARE\\");
      psVar7 = (short *)(**(code **)(*local_28 + 0x28))(uVar5);
      piVar6 = FUN_100082c0(piVar6,psVar7);
      pwVar9 = L"\\About";
    }
    FUN_100082c0(piVar6,pwVar9);
    FUN_10005a40(local_128,&pvStack_190);
    FUN_10005380(param_2,(int *)&pvStack_190);
    if ((wchar_t *)0x7 < local_17c) {
      pvVar15 = pvStack_190;
      if ((0xfff < (int)local_17c * 2 + 2U) &&
         (pvVar15 = *(void **)((int)pvStack_190 + -4),
         0x1f < (uint)((int)pvStack_190 + (-4 - (int)pvVar15)))) goto LAB_1000de82;
      FUN_1002e346(pvVar15);
    }
    FUN_1000de90(local_140);
    goto LAB_1000de25;
  }
  puStack_20 = &stack0xfffffffc;
  _memset(local_140,0,0xb0);
  FUN_1000dfd0(local_140);
  local_14 = 0;
  piVar6 = FUN_100082c0(local_130,L"SOFTWARE\\");
  psVar7 = (short *)(**(code **)(*local_28 + 0x28))();
  piVar6 = FUN_100082c0(piVar6,psVar7);
  FUN_100082c0(piVar6,L"\\Install");
  FUN_10005a40(local_128,&local_1c8);
  uVar5 = uStack_1b4;
  pppWVar4 = local_1c8;
  local_198 = 0x80000002;
  local_184 = CONCAT44(uStack_1b4,local_1b8);
  local_2c = (undefined **)0x0;
  local_194 = local_1c8;
  pvStack_190 = pvStack_1c4;
  uStack_18c = uStack_1c0;
  uStack_188 = uStack_1bc;
  local_1b8 = 0;
  uStack_1b4 = 7;
  local_1c8 = (LPCWSTR **)((uint)local_1c8 & 0xffff0000);
  local_17c = L"InstallPath";
  local_3c = (void *)0x0;
  local_38 = &PTR_vftable_10069aa8;
  ppppWVar14 = &local_194;
  if (7 < uVar5) {
    ppppWVar14 = (LPCWSTR ***)pppWVar4;
  }
  FUN_10009ff0(&local_54,&local_198,(LPCWSTR)ppppWVar14,L"InstallPath",(int *)&local_3c);
  local_90 = local_3c;
  local_14._0_1_ = 4;
  if (local_3c != (void *)0x0) {
    local_1b0 = (void *)0x0;
    local_1a0 = 0;
    uStack_19c = 0xf;
    FUN_10008e70(&local_1b0,(uint *)"failed winapi::reg::get_string_value",0x24);
    ppuStack_8c = &PTR_vftable_10069ab8;
    pvStack_88 = local_1b0;
    uStack_84 = uStack_1ac;
    local_70 = '\x01';
    local_78 = CONCAT44(uStack_19c,local_1a0);
    local_14._0_1_ = 3;
    local_28 = (int *)0xe;
    if (uStack_40 < 8) goto LAB_1000d6ae;
    pvVar15 = local_54;
    if ((uStack_40 * 2 + 2 < 0x1000) ||
       (pvVar15 = *(void **)((int)local_54 + -4), (uint)((int)local_54 + (-4 - (int)pvVar15)) < 0x20
       )) {
      FUN_1002e346(pvVar15);
      goto LAB_1000d6ae;
    }
LAB_1000de45:
    FUN_10032f7f();
LAB_1000de4a:
    FUN_10032f7f();
LAB_1000de4f:
    FUN_10032f7f();
    goto LAB_1000de54;
  }
  local_70 = '\0';
  local_28 = (int *)0x6;
  local_90 = local_54;
  ppuStack_8c = ppuStack_50;
  pvStack_88 = pvStack_4c;
  uStack_84 = uStack_48;
LAB_1000d6ae:
  local_14._0_1_ = 6;
  if (7 < local_184._4_4_) {
    ppppWVar14 = (LPCWSTR ***)local_194;
    if ((0xfff < local_184._4_4_ * 2 + 2) &&
       (ppppWVar14 = (LPCWSTR ***)local_194[-1],
       0x1f < (uint)((int)local_194 + (-4 - (int)ppppWVar14)))) goto LAB_1000de45;
    FUN_1002e346(ppppWVar14);
  }
  local_184 = 0x700000000;
  local_194 = (LPCWSTR **)((uint)local_194 & 0xffff0000);
  local_198 = 0;
  local_14._0_1_ = 8;
  if (7 < uStack_1b4) {
    ppppWVar14 = (LPCWSTR ***)local_1c8;
    if ((0xfff < uStack_1b4 * 2 + 2) &&
       (ppppWVar14 = (LPCWSTR ***)local_1c8[-1],
       0x1f < (uint)((int)local_1c8 + (-4 - (int)ppppWVar14)))) goto LAB_1000de45;
    FUN_1002e346(ppppWVar14);
  }
  if (local_70 == '\0') {
    local_34 = local_34 & 0xffffffff;
    local_2c = &PTR_vftable_10069aa8;
    puVar8 = (undefined4 *)FUN_1000bfd0(&local_1b0,(DWORD *)((int)&local_34 + 4));
    local_6c = (void *)*puVar8;
    uStack_68 = puVar8[1];
    uStack_64 = puVar8[2];
    uStack_60 = puVar8[3];
    local_5c = *(undefined8 *)(puVar8 + 4);
    puVar8[4] = 0;
    puVar8[5] = 7;
    *(undefined2 *)puVar8 = 0;
    local_14._0_1_ = 9;
    if (7 < uStack_19c) {
      pvVar15 = local_1b0;
      if ((0xfff < uStack_19c * 2 + 2) &&
         (pvVar15 = *(void **)((int)local_1b0 + -4),
         0x1f < (uint)((int)local_1b0 + (-4 - (int)pvVar15)))) goto LAB_1000de4a;
      FUN_1002e346(pvVar15);
    }
    local_1a0 = 0;
    uStack_19c = 7;
    local_1b0 = (void *)((uint)local_1b0 & 0xffff0000);
    if (local_34._4_4_ == 0) {
      pwVar9 = (wchar_t *)FUN_1000b810(&local_6c,&pvStack_190);
      local_28 = (int *)((uint)local_28 | 1);
      if (7 < *(uint *)(pwVar9 + 10)) {
        pwVar9 = *(wchar_t **)pwVar9;
      }
      iVar10 = __wcsicmp(pwVar9,L"bdsubwiz");
      local_175 = '\0';
      if (iVar10 != 0) goto LAB_1000d85a;
    }
    else {
LAB_1000d85a:
      local_175 = '\x01';
    }
    if ((((uint)local_28 & 1) != 0) && ((wchar_t *)0x7 < local_17c)) {
      pvVar15 = pvStack_190;
      if ((0xfff < (int)local_17c * 2 + 2U) &&
         (pvVar15 = *(void **)((int)pvStack_190 + -4),
         0x1f < (uint)((int)pvStack_190 + (-4 - (int)pvVar15)))) goto LAB_1000de4f;
      FUN_1002e346(pvVar15);
    }
    if (local_175 == '\0') {
      if (local_70 != '\0') goto LAB_1000de54;
      local_38 = (undefined **)((uint)local_38 & 0xffffff00);
      FUN_10018950(&local_54,(uint *)&local_90);
      local_14._0_1_ = 10;
      FUN_1000bdf0(local_174,(uint *)&local_54);
      local_14._0_1_ = 0xc;
      if (uStack_40 < 8) {
LAB_1000d941:
        if (local_144 == '\0') {
          local_38 = (undefined **)((uint)local_38 & 0xffffff00);
          FUN_10018cc0((LPWSTR)&pvStack_190,local_15c);
          local_14._0_1_ = 0xd;
          if (local_70 != '\0') {
LAB_1000de54:
            local_2c = (undefined **)0x0;
            local_34 = 0;
            FUN_1000ee00((undefined4 *)&local_34);
                    /* WARNING: Subroutine does not return */
            __CxxThrowException_8(extraout_ECX,&DAT_10067650);
          }
          local_38 = (undefined **)((uint)local_38 & 0xffffff00);
          FUN_10018950(&local_1c8,(uint *)&local_90);
          local_14._0_1_ = 0xe;
          puVar11 = (uint *)FUN_1000b910(&local_1b0,(uint *)&local_1c8,(uint *)&pvStack_190);
          local_14._0_1_ = 0xf;
          FUN_1000eb70(&local_54,puVar11);
          FUN_10005380(param_2,(int *)&local_54);
          if (7 < uStack_40) {
            pvVar15 = local_54;
            if ((uStack_40 * 2 + 2 < 0x1000) ||
               (pvVar15 = *(void **)((int)local_54 + -4),
               (uint)((int)local_54 + (-4 - (int)pvVar15)) < 0x20)) {
              FUN_1002e346(pvVar15);
              goto LAB_1000da09;
            }
LAB_1000de78:
            FUN_10032f7f();
            goto LAB_1000de7d;
          }
LAB_1000da09:
          if (7 < uStack_19c) {
            pvVar15 = local_1b0;
            if ((0xfff < uStack_19c * 2 + 2) &&
               (pvVar15 = *(void **)((int)local_1b0 + -4),
               0x1f < (uint)((int)local_1b0 + (-4 - (int)pvVar15)))) goto LAB_1000de78;
            FUN_1002e346(pvVar15);
          }
          local_1a0 = 0;
          uStack_19c = 7;
          local_1b0 = (void *)((uint)local_1b0 & 0xffff0000);
          if (7 < uStack_1b4) {
            ppppWVar14 = (LPCWSTR ***)local_1c8;
            if ((0xfff < uStack_1b4 * 2 + 2) &&
               (ppppWVar14 = (LPCWSTR ***)local_1c8[-1],
               0x1f < (uint)((int)local_1c8 + (-4 - (int)ppppWVar14)))) goto LAB_1000de78;
            FUN_1002e346(ppppWVar14);
          }
          if ((wchar_t *)0x7 < local_17c) {
            pvVar15 = pvStack_190;
            if ((0xfff < (int)local_17c * 2 + 2U) &&
               (pvVar15 = *(void **)((int)pvStack_190 + -4),
               0x1f < (uint)((int)pvStack_190 + (-4 - (int)pvVar15)))) goto LAB_1000de78;
            FUN_1002e346(pvVar15);
          }
          local_175 = '\x01';
        }
        else {
          local_175 = '\0';
        }
        FUN_1000e2c0((int *)local_174);
        goto LAB_1000daf8;
      }
      pvVar15 = local_54;
      if ((uStack_40 * 2 + 2 < 0x1000) ||
         (pvVar15 = *(void **)((int)local_54 + -4),
         (uint)((int)local_54 + (-4 - (int)pvVar15)) < 0x20)) {
        FUN_1002e346(pvVar15);
        goto LAB_1000d941;
      }
LAB_1000de7d:
      FUN_10032f7f();
LAB_1000de82:
      FUN_10032f7f();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    if (local_70 != '\0') goto LAB_1000de54;
    FUN_10005380(param_2,(int *)&local_90);
    local_175 = '\x01';
LAB_1000daf8:
    if (7 < local_5c._4_4_) {
      pvVar15 = local_6c;
      if ((0xfff < local_5c._4_4_ * 2 + 2) &&
         (pvVar15 = *(void **)((int)local_6c + -4),
         0x1f < (uint)((int)local_6c + (-4 - (int)pvVar15)))) goto LAB_1000de7d;
      FUN_1002e346(pvVar15);
    }
    local_5c = 0x700000000;
    local_6c = (void *)((uint)local_6c & 0xffff0000);
  }
  else {
    local_175 = '\0';
  }
  FUN_1000e210((int *)&local_90);
  FUN_1000de90(local_140);
LAB_1000de25:
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000de90 @ 1000de90