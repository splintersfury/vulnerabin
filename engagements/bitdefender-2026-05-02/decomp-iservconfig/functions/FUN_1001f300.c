void FUN_1001f300(void)

{
  code *pcVar1;
  char cVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  HMODULE hModule;
  HRSRC hResInfo;
  HGLOBAL hResData;
  DWORD DVar7;
  ushort ******ppppppuVar8;
  ushort ******ppppppuVar9;
  void *pvVar10;
  uint uStack_4f0;
  void *local_4e0 [4];
  undefined4 local_4d0;
  uint local_4cc;
  _Facet_base local_4bc [4];
  _Locimp *local_4b8;
  undefined *local_4b4;
  undefined1 local_4b0 [1048];
  uint local_98 [4];
  void *local_88 [4];
  undefined4 local_78;
  uint local_74;
  char local_70 [8];
  DWORD local_68;
  undefined **local_64;
  void *local_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined8 local_4c;
  ushort *****local_44 [4];
  int local_34;
  uint local_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004fc51;
  local_1c = ExceptionList;
  uStack_4f0 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_4f0;
  ExceptionList = &local_1c;
  local_2c = uStack_4f0;
  FUN_1000c210(local_4b0,L"ProductInfo::Load");
  local_14 = 0;
  local_4b4 = &DAT_1006b708;
  FUN_100218c0(&local_4b4,local_98);
  local_14._0_1_ = 1;
  if (((char)local_78 == '\0') && (cVar2 = FUN_1001f880((char *)local_98), cVar2 != '\0')) {
    FUN_1000e5a0((char *)local_98);
    FUN_1000c320((int)local_4b0);
    goto LAB_1001f4ad;
  }
  FUN_1000e5a0((char *)local_98);
  local_68 = 0;
  local_64 = &PTR_vftable_10069aa8;
  puVar3 = (undefined4 *)FUN_1000bfd0(local_88,&local_68);
  local_5c = (void *)*puVar3;
  uStack_58 = puVar3[1];
  uStack_54 = puVar3[2];
  uStack_50 = puVar3[3];
  local_4c = *(undefined8 *)(puVar3 + 4);
  puVar3[4] = 0;
  puVar3[5] = 7;
  *(undefined2 *)puVar3 = 0;
  local_14._0_1_ = 2;
  if (7 < local_74) {
    pvVar10 = local_88[0];
    if ((local_74 * 2 + 2 < 0x1000) ||
       (pvVar10 = *(void **)((int)local_88[0] + -4),
       (uint)((int)local_88[0] + (-4 - (int)pvVar10)) < 0x20)) {
      FUN_1002e346(pvVar10);
      goto LAB_1001f450;
    }
LAB_1001f864:
    FUN_10032f7f();
LAB_1001f869:
    FUN_10032f7f();
LAB_1001f86e:
    FUN_10032f7f();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
LAB_1001f450:
  if (local_68 == 0) {
    local_14._0_1_ = 3;
    local_4b8 = std::locale::_Init(true);
    local_14._0_1_ = 4;
    puVar5 = (uint *)FUN_1000b810(&local_5c,local_88);
    local_14._0_1_ = 5;
    FUN_1000eb70(local_4e0,puVar5);
    local_14._0_1_ = 6;
    FUN_10023600(local_44,local_4e0,local_4bc);
    local_14._0_1_ = 8;
    if (7 < local_4cc) {
      pvVar10 = local_4e0[0];
      if ((local_4cc * 2 + 2 < 0x1000) ||
         (pvVar10 = *(void **)((int)local_4e0[0] + -4),
         (uint)((int)local_4e0[0] + (-4 - (int)pvVar10)) < 0x20)) {
        FUN_1002e346(pvVar10);
        goto LAB_1001f55f;
      }
      goto LAB_1001f869;
    }
LAB_1001f55f:
    local_4d0 = 0;
    local_4cc = 7;
    local_4e0[0] = (void *)((uint)local_4e0[0] & 0xffff0000);
    local_14._0_1_ = 9;
    if (7 < local_74) {
      pvVar10 = local_88[0];
      if ((0xfff < local_74 * 2 + 2) &&
         (pvVar10 = *(void **)((int)local_88[0] + -4),
         0x1f < (uint)((int)local_88[0] + (-4 - (int)pvVar10)))) goto LAB_1001f869;
      FUN_1002e346(pvVar10);
    }
    local_78 = 0;
    local_74 = 7;
    local_88[0] = (void *)((uint)local_88[0] & 0xffff0000);
    local_14._0_1_ = 10;
    if ((local_4b8 != (_Locimp *)0x0) &&
       (puVar3 = (undefined4 *)(**(code **)(*(int *)local_4b8 + 8))(), puVar3 != (undefined4 *)0x0))
    {
      (**(code **)*puVar3)(1);
    }
    uVar4 = local_30;
    ppppppuVar9 = (ushort ******)local_44[0];
    ppppppuVar8 = local_44;
    if (7 < local_30) {
      ppppppuVar8 = (ushort ******)local_44[0];
    }
    if ((local_34 == 0x13) &&
       (iVar6 = FUN_10009c60((ushort *)ppppppuVar8,(ushort *)L"productagentservice",0x13),
       iVar6 == 0)) {
LAB_1001f68b:
      hModule = GetModuleHandleW((LPCWSTR)0x0);
      hResInfo = FindResourceW(hModule,(LPCWSTR)0xc350,L"SETTINGS");
      ppppppuVar9 = (ushort ******)local_44[0];
      uVar4 = local_30;
      if ((hResInfo != (HRSRC)0x0) &&
         (hResData = LoadResource(hModule,hResInfo), ppppppuVar9 = (ushort ******)local_44[0],
         uVar4 = local_30, hResData != (HGLOBAL)0x0)) {
        local_4b4 = (undefined *)LockResource(hResData);
        DVar7 = SizeofResource(hModule,hResInfo);
        local_14._0_1_ = 0xb;
        FUN_100236d0(local_70,(int)local_4b4,(int)(local_4b4 + DVar7),1);
        local_14._0_1_ = 0xc;
        cVar2 = FUN_1001f880(local_70);
        if (cVar2 == '\0') {
          FUN_1000e760(local_70);
          FUN_1001f7dd();
          return;
        }
        FUN_1000e760(local_70);
        if (7 < local_30) {
          ppppppuVar9 = (ushort ******)local_44[0];
          if ((0xfff < local_30 * 2 + 2) &&
             (ppppppuVar9 = (ushort ******)local_44[0][-1],
             0x1f < (uint)((int)local_44[0] + (-4 - (int)ppppppuVar9)))) goto LAB_1001f86e;
          FUN_1002e346(ppppppuVar9);
        }
        local_34 = 0;
        local_30 = 7;
        local_44[0] = (ushort *****)((uint)local_44[0] & 0xffff0000);
        if (7 < local_4c._4_4_) {
          pvVar10 = local_5c;
          if ((0xfff < local_4c._4_4_ * 2 + 2) &&
             (pvVar10 = *(void **)((int)local_5c + -4),
             0x1f < (uint)((int)local_5c + (-4 - (int)pvVar10)))) goto LAB_1001f86e;
          FUN_1002e346(pvVar10);
        }
        local_4c = 0x700000000;
        local_5c = (void *)((uint)local_5c & 0xffff0000);
        FUN_1000c320((int)local_4b0);
        goto LAB_1001f4ad;
      }
    }
    else {
      ppppppuVar8 = local_44;
      if (7 < uVar4) {
        ppppppuVar8 = ppppppuVar9;
      }
      if ((local_34 == 0xe) &&
         (iVar6 = FUN_10009c60((ushort *)ppppppuVar8,(ushort *)L"productagentui",0xe), iVar6 == 0))
      goto LAB_1001f68b;
      ppppppuVar8 = local_44;
      if (7 < uVar4) {
        ppppppuVar8 = ppppppuVar9;
      }
      if ((local_34 == 8) &&
         (iVar6 = FUN_10009c60((ushort *)ppppppuVar8,(ushort *)L"watchdog",8), iVar6 == 0))
      goto LAB_1001f68b;
      ppppppuVar8 = local_44;
      if (7 < uVar4) {
        ppppppuVar8 = ppppppuVar9;
      }
      if ((local_34 == 0xc) &&
         (iVar6 = FUN_10009c60((ushort *)ppppppuVar8,(ushort *)L"discoverysrv",0xc), iVar6 == 0))
      goto LAB_1001f68b;
    }
    if (7 < uVar4) {
      ppppppuVar8 = ppppppuVar9;
      if ((uVar4 * 2 + 2 < 0x1000) ||
         (ppppppuVar8 = (ushort ******)ppppppuVar9[-1],
         (uint)((int)ppppppuVar9 + (-4 - (int)ppppppuVar8)) < 0x20)) {
        FUN_1002e346(ppppppuVar8);
        goto LAB_1001f813;
      }
LAB_1001f85f:
      FUN_10032f7f();
      goto LAB_1001f864;
    }
LAB_1001f813:
    local_34 = 0;
    local_30 = 7;
    local_44[0] = (ushort *****)((uint)local_44[0] & 0xffff0000);
    if (7 < local_4c._4_4_) {
      pvVar10 = local_5c;
      if (0xfff < local_4c._4_4_ * 2 + 2) {
        pvVar10 = *(void **)((int)local_5c + -4);
        uVar4 = (int)local_5c + (-4 - (int)pvVar10);
        goto joined_r0x1001f859;
      }
      goto LAB_1001f486;
    }
  }
  else if (7 < local_4c._4_4_) {
    pvVar10 = local_5c;
    if (0xfff < local_4c._4_4_ * 2 + 2) {
      pvVar10 = *(void **)((int)local_5c + -4);
      uVar4 = (int)local_5c + (-4 - (int)pvVar10);
joined_r0x1001f859:
      if (0x1f < uVar4) goto LAB_1001f85f;
    }
LAB_1001f486:
    FUN_1002e346(pvVar10);
  }
  local_4c = 0x700000000;
  local_5c = (void *)((uint)local_5c & 0xffff0000);
  FUN_1000c320((int)local_4b0);
LAB_1001f4ad:
  ExceptionList = local_1c;
  FUN_1002e315(local_2c ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@1001f7d1 @ 1001f7d1