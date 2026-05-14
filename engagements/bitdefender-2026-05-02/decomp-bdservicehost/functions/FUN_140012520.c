void FUN_140012520(longlong *param_1,LPCWSTR param_2,undefined8 param_3,DWORD *param_4)

{
  longlong *plVar1;
  code *pcVar2;
  longlong *plVar3;
  HMODULE pHVar4;
  HMODULE pHVar5;
  HMODULE pHVar6;
  bool bVar7;
  DWORD DVar8;
  HMODULE hModule;
  HMODULE pHVar9;
  HMODULE pHVar10;
  undefined8 uVar11;
  HMODULE pHVar12;
  longlong *plVar13;
  ulonglong uVar14;
  undefined1 auStack_c8 [32];
  HMODULE local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  HMODULE *local_90;
  undefined8 local_88;
  longlong *local_80;
  HMODULE local_78;
  HMODULE pHStack_70;
  HMODULE local_68;
  ulonglong local_60 [2];
  undefined8 local_50;
  ulonglong local_48;
  ulonglong local_40;
  
  local_40 = DAT_14007a060 ^ (ulonglong)auStack_c8;
  local_78 = (HMODULE)0x0;
  pHStack_70 = (HMODULE)0x0;
  local_68 = (HMODULE)0x0;
  local_80 = param_1;
  hModule = LoadLibraryW(param_2);
  pHVar12 = (HMODULE)0x0;
  if (hModule == (HMODULE)0x0) {
    uVar14 = 0xffffffffffffffff;
    do {
      uVar14 = uVar14 + 1;
    } while (param_2[uVar14] != L'\0');
    local_60[0] = 0;
    local_50 = 0;
    local_48 = 7;
    FUN_140010340((longlong *)local_60,(undefined8 *)param_2,uVar14);
    bVar7 = FUN_140005730((uint *)local_60);
    if (bVar7) {
      hModule = LoadLibraryExW(param_2,(HANDLE)0x0,8);
    }
    DVar8 = GetLastError();
    *param_4 = DVar8;
    if (7 < local_48) {
      if ((0xfff < local_48 * 2 + 2) && (0x1f < (local_60[0] - *(longlong *)(local_60[0] - 8)) - 8))
      {
        FUN_140035d28();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      FUN_14002f180();
    }
    local_50 = 0;
    local_48 = 7;
    local_60[0] = local_60[0] & 0xffffffffffff0000;
  }
  pHVar10 = pHVar12;
  if (hModule == (HMODULE)0x0) {
    local_78 = (HMODULE)0x0;
    pHStack_70 = (HMODULE)0x0;
    local_68 = (HMODULE)0x0;
    hModule = pHVar12;
    pHVar9 = pHVar12;
    pHVar4 = local_78;
    pHVar5 = pHStack_70;
    pHVar6 = local_68;
  }
  else {
    pHVar9 = (HMODULE)GetProcAddress(hModule,"BdCreateObject");
    if (pHVar9 == (HMODULE)0x0) {
      DVar8 = GetLastError();
      *param_4 = DVar8;
      local_78 = (HMODULE)0x0;
      pHStack_70 = (HMODULE)0x0;
      local_68 = (HMODULE)0x0;
      FreeLibrary(hModule);
      hModule = pHVar12;
      pHVar9 = pHVar12;
      pHVar4 = local_78;
      pHVar5 = pHStack_70;
      pHVar6 = local_68;
    }
    else {
      pHVar10 = (HMODULE)GetProcAddress(hModule,"BdDestroyObject");
      pHVar4 = hModule;
      pHVar5 = pHVar9;
      pHVar6 = pHVar10;
      if (pHVar10 == (HMODULE)0x0) {
        DVar8 = GetLastError();
        *param_4 = DVar8;
        local_78 = (HMODULE)0x0;
        pHVar9 = (HMODULE)0x0;
        pHStack_70 = (HMODULE)0x0;
        pHVar10 = (HMODULE)0x0;
        local_68 = (HMODULE)0x0;
        FreeLibrary(hModule);
        hModule = (HMODULE)0x0;
        pHVar4 = local_78;
        pHVar5 = pHStack_70;
        pHVar6 = local_68;
      }
    }
  }
  local_68 = pHVar6;
  pHStack_70 = pHVar5;
  local_78 = pHVar4;
  if (hModule == (HMODULE)0x0) {
    *param_1 = 0;
LAB_14001294b:
    param_1[1] = (longlong)pHVar12;
    goto LAB_14001294f;
  }
  local_80 = (longlong *)0x0;
  local_90 = (HMODULE *)0x983304d0414e2323;
  local_88 = 0xe952825d7c884176;
  DVar8 = (*(code *)PTR__guard_dispatch_icall_14005b538)(L"productinfo",&local_90,&local_80);
  plVar3 = local_80;
  *param_4 = DVar8;
  if (DVar8 == 0) {
    DVar8 = (*(code *)PTR__guard_dispatch_icall_14005b538)(local_80,0);
    *param_4 = DVar8;
    if (DVar8 == 0) {
      DVar8 = (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar3);
      *param_4 = DVar8;
      if (DVar8 == 0) {
        local_a8 = (HMODULE)0x666b97245666c9d0;
        local_a0 = 0xf666c93d61084666;
        pHVar12 = (HMODULE)(*(code *)PTR__guard_dispatch_icall_14005b538)(plVar3);
        if (pHVar12 != (HMODULE)0x0) {
          plVar13 = (longlong *)operator_new(0x48);
          *plVar13 = 0;
          plVar13[1] = 0;
          plVar13[2] = 0;
          plVar13[3] = 0;
          plVar13[4] = 0;
          plVar13[5] = 0;
          plVar13[6] = 0;
          plVar13[7] = 0;
          plVar13[8] = 0;
          local_78 = (HMODULE)0x0;
          pHStack_70 = (HMODULE)0x0;
          local_68 = (HMODULE)0x0;
          local_90 = &local_a8;
          *plVar13 = (longlong)bd::framework::details::exported_plugin_releaser::vftable;
          local_a8 = (HMODULE)0x0;
          plVar13[1] = (longlong)hModule;
          plVar13[2] = (longlong)pHVar9;
          plVar13[3] = (longlong)pHVar10;
          local_a0 = 0;
          local_98 = 0;
          plVar1 = plVar13 + 4;
          *plVar1 = 0;
          plVar13[6] = 0;
          plVar13[7] = 7;
          *(undefined2 *)plVar1 = 0;
          local_80 = plVar13;
          FUN_140010340(plVar1,(undefined8 *)L"productinfo",0xb);
          plVar13[8] = (longlong)plVar3;
          if (local_a8 != (HMODULE)0x0) {
            FreeLibrary(local_a8);
          }
          *param_1 = (longlong)plVar13;
          goto LAB_14001294b;
        }
        *param_4 = 0x1f;
        (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar3);
        (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar3);
        local_a8 = (HMODULE)0xbc90fca366551ab3;
        local_a0 = 0x514be292f7c5425f;
        (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar3,&local_a8);
        (*(code *)PTR__guard_dispatch_icall_14005b538)(L"productinfo");
        *param_1 = 0;
        param_1[1] = 0;
        goto LAB_14001286f;
      }
      (*(code *)PTR__guard_dispatch_icall_14005b538)();
    }
    local_a8 = (HMODULE)0xbc90fca366551ab3;
    local_a0 = 0x514be292f7c5425f;
    uVar11 = (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar3,&local_a8);
    (*(code *)PTR__guard_dispatch_icall_14005b538)(L"productinfo",uVar11);
    *param_1 = 0;
    param_1[1] = 0;
  }
  else {
    *param_1 = 0;
    param_1[1] = 0;
  }
LAB_14001286f:
  if (hModule != (HMODULE)0x0) {
    FreeLibrary(hModule);
  }
LAB_14001294f:
  FUN_14002f160(local_40 ^ (ulonglong)auStack_c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140012980 @ 140012980