void FUN_140012190(undefined8 *param_1,LPCWSTR param_2,undefined8 param_3,ushort *param_4)

{
  ushort *puVar1;
  ushort uVar2;
  ushort uVar3;
  HMODULE pHVar4;
  char cVar5;
  DWORD DVar6;
  HANDLE hObject;
  HMODULE *ppHVar7;
  ushort ****ppppuVar8;
  longlong lVar9;
  bool bVar10;
  bool bVar11;
  undefined1 auStackY_1c8 [32];
  HMODULE local_188;
  undefined4 uStack_180;
  undefined4 uStack_17c;
  char local_178 [8];
  HMODULE local_170;
  undefined4 uStack_168;
  undefined4 uStack_164;
  char local_160 [8];
  HMODULE local_158 [2];
  char local_148;
  undefined8 local_140;
  undefined4 uStack_138;
  undefined4 uStack_134;
  char local_130;
  undefined8 local_128;
  undefined8 uStack_120;
  HMODULE local_118 [2];
  ulonglong local_108 [8];
  ushort ***local_c8 [2];
  longlong local_b8;
  ulonglong local_b0;
  longlong local_a8 [14];
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStackY_1c8;
  local_118[0] = (HMODULE)((ulonglong)local_118[0] & 0xffffffff00000000);
  hObject = CreateFileW(param_2,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,
                        (HANDLE)0xffffffffffffffff);
  if (hObject == (HANDLE)0xffffffffffffffff) {
    DVar6 = GetLastError();
    local_128 = (HMODULE)CONCAT44(local_128._4_4_,DVar6);
    uStack_120 = &PTR_vftable_14007ad08;
    *param_1 = local_128;
    param_1[1] = &PTR_vftable_14007ad08;
    *(undefined1 *)(param_1 + 2) = 1;
    goto LAB_1400124e4;
  }
  local_128 = (HMODULE)0x0;
  uStack_120 = &PTR_vftable_14007ac70;
  cVar5 = FUN_140005250(param_2,(DWORD *)&local_128);
  if (cVar5 == '\0') {
LAB_1400122ed:
    bVar11 = false;
    bVar10 = true;
    local_128 = (HMODULE)CONCAT44(local_128._4_4_,0x2ae);
    uStack_120 = &PTR_vftable_14007ad08;
    local_140 = (HMODULE)CONCAT44(local_128._4_4_,0x2ae);
    uStack_138 = 0x4007ad08;
    uStack_134 = 1;
    local_130 = '\x01';
    ppHVar7 = (HMODULE *)&local_140;
  }
  else {
    local_128 = (HMODULE)0x0;
    uStack_120 = &PTR_vftable_14007ac70;
    FUN_1400045c0(local_108,param_2,(int *)&local_128);
    if ((uStack_120[1] != DAT_14007ac78) || ((DWORD)local_128 != 0)) {
LAB_1400122db:
      FUN_1400039f0(local_a8);
      FUN_1400039f0((longlong *)local_108);
      goto LAB_1400122ed;
    }
    puVar1 = param_4 + 8;
    if (7 < *(ulonglong *)(param_4 + 0xc)) {
      param_4 = *(ushort **)param_4;
    }
    ppppuVar8 = local_c8;
    if (7 < local_b0) {
      ppppuVar8 = (ushort ****)local_c8[0];
    }
    if (local_b8 != *(longlong *)puVar1) goto LAB_1400122db;
    if (local_b8 != 0) {
      uVar2 = *(ushort *)ppppuVar8;
      uVar3 = *param_4;
      if (uVar3 <= uVar2) {
        lVar9 = (longlong)ppppuVar8 - (longlong)param_4;
        bVar10 = uVar2 < uVar3;
        bVar11 = uVar2 == uVar3;
        do {
          if (!bVar10 && !bVar11) break;
          if (local_b8 == 1) goto LAB_140012340;
          local_b8 = local_b8 + -1;
          param_4 = param_4 + 1;
          uVar2 = *(ushort *)((longlong)param_4 + lVar9);
          bVar10 = uVar2 < *param_4;
          bVar11 = uVar2 == *param_4;
        } while (!bVar10);
      }
      goto LAB_1400122db;
    }
LAB_140012340:
    FUN_1400039f0(local_a8);
    FUN_1400039f0((longlong *)local_108);
    local_128 = (HMODULE)0x0;
    uStack_120 = &PTR_vftable_14007ac70;
    local_118[0] = (HMODULE)0x0;
    FUN_140003820(local_118,param_2,&local_128);
    if ((uStack_120[1] == DAT_14007ac78) && ((DWORD)local_128 == 0)) {
      bVar11 = true;
      bVar10 = false;
      local_158[0] = local_118[0];
      local_118[0] = (HMODULE)0x0;
      local_148 = '\0';
      ppHVar7 = local_158;
    }
    else {
      bVar11 = false;
      bVar10 = true;
      local_170 = local_128;
      uStack_168 = (undefined4)uStack_120;
      uStack_164 = uStack_120._4_4_;
      local_160[0] = '\x01';
      ppHVar7 = &local_170;
    }
    local_178[0] = -1;
    if (*(char *)(ppHVar7 + 2) != -1) {
      if (*(char *)(ppHVar7 + 2) == '\0') {
        local_188 = *ppHVar7;
        *ppHVar7 = (HMODULE)0x0;
        local_178[0] = '\0';
      }
      else {
        local_188 = *ppHVar7;
        uStack_180 = *(undefined4 *)(ppHVar7 + 1);
        uStack_17c = *(undefined4 *)((longlong)ppHVar7 + 0xc);
        local_178[0] = '\x01';
      }
    }
    if (bVar10) {
      if (((local_160[0] != -1) && (local_160[0] == '\0')) && (local_170 != (HMODULE)0x0)) {
        FreeLibrary(local_170);
        local_170 = (HMODULE)0x0;
      }
    }
    if (bVar11) {
      if (((local_148 != -1) && (local_148 == '\0')) && (local_158[0] != (HMODULE)0x0)) {
        FreeLibrary(local_158[0]);
        local_158[0] = (HMODULE)0x0;
      }
    }
    bVar11 = true;
    bVar10 = false;
    if (local_118[0] != (HMODULE)0x0) {
      FreeLibrary(local_118[0]);
    }
    ppHVar7 = &local_188;
  }
  *(undefined1 *)(param_1 + 2) = 0xff;
  if (*(char *)(ppHVar7 + 2) != -1) {
    if (*(char *)(ppHVar7 + 2) == '\0') {
      pHVar4 = *ppHVar7;
      *ppHVar7 = (HMODULE)0x0;
      *param_1 = pHVar4;
      if (*ppHVar7 != (HMODULE)0x0) {
        FreeLibrary(*ppHVar7);
      }
      *ppHVar7 = (HMODULE)0x0;
      *(undefined1 *)(param_1 + 2) = 0;
    }
    else {
      pHVar4 = ppHVar7[1];
      *param_1 = *ppHVar7;
      param_1[1] = pHVar4;
      *(undefined1 *)(param_1 + 2) = 1;
    }
  }
  if (bVar10) {
    if (((local_130 != -1) && (local_130 == '\0')) && (local_140 != (HMODULE)0x0)) {
      FreeLibrary(local_140);
      local_140 = (HMODULE)0x0;
    }
  }
  if ((((bVar11) && (local_178[0] != -1)) && (local_178[0] == '\0')) && (local_188 != (HMODULE)0x0))
  {
    FreeLibrary(local_188);
    local_188 = (HMODULE)0x0;
  }
  CloseHandle(hObject);
LAB_1400124e4:
  FUN_14002f160(local_38 ^ (ulonglong)auStackY_1c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140012520 @ 140012520