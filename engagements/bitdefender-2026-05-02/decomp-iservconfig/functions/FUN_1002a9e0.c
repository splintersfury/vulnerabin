void FUN_1002a9e0(void)

{
  int *piVar1;
  short sVar2;
  code *pcVar3;
  int iVar4;
  int iVar5;
  undefined1 uVar6;
  int *piVar7;
  HRESULT HVar8;
  int iVar9;
  wchar_t ****ppppwVar10;
  char cVar11;
  short *psVar12;
  undefined *puVar13;
  undefined4 *puVar14;
  short sVar15;
  void *pvVar16;
  uint uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined *local_4ac;
  int iStack_4a8;
  int iStack_4a4;
  int iStack_4a0;
  undefined4 local_49c;
  uint uStack_498;
  undefined4 *local_494;
  undefined **local_490;
  HRESULT local_48c;
  uint local_488;
  undefined4 local_484;
  char local_47d;
  short *local_47c;
  undefined1 local_478 [872];
  int local_110 [24];
  undefined **local_b0 [20];
  int local_60;
  undefined **local_5c;
  wchar_t ***local_58 [4];
  undefined4 local_48;
  uint local_44;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  int *local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  puStack_18 = &LAB_10050ba1;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_488 = 0;
  local_30 = 0;
  local_28 = (int *)0x0;
  local_14 = 1;
  FUN_1002b2b0((int *)&local_30);
  piVar7 = (int *)FUN_100288d0(&local_4ac);
  local_14._0_1_ = 2;
  if (local_30._4_4_ == local_28) {
    FUN_1002b3f0(&local_30,local_30._4_4_,piVar7);
  }
  else {
    *local_30._4_4_ = 0;
    local_30._4_4_[4] = 0;
    local_30._4_4_[5] = 0;
    iVar9 = piVar7[1];
    iVar4 = piVar7[2];
    iVar5 = piVar7[3];
    *local_30._4_4_ = *piVar7;
    local_30._4_4_[1] = iVar9;
    local_30._4_4_[2] = iVar4;
    local_30._4_4_[3] = iVar5;
    *(undefined8 *)(local_30._4_4_ + 4) = *(undefined8 *)(piVar7 + 4);
    piVar7[4] = 0;
    piVar7[5] = 7;
    *(undefined2 *)piVar7 = 0;
    local_30 = CONCAT44(local_30._4_4_ + 6,(int *)local_30);
  }
  local_14._0_1_ = 1;
  uVar6 = (undefined1)local_14;
  local_14._0_1_ = 1;
  if (uStack_498 < 8) {
LAB_1002ab17:
    piVar7 = FUN_100034b0(local_110,0x10,0x10061564);
    local_14 = CONCAT31(local_14._1_3_,3);
    cVar11 = (char)piVar7[0x12];
    if (cVar11 != '\0') {
      FUN_100082c0(piVar7,L"machine guid=");
      cVar11 = (char)piVar7[0x12];
    }
    puVar14 = (undefined4 *)((int)local_30._4_4_ + -0x18);
    if (cVar11 != '\0') {
      if (7 < *(uint *)((int)local_30._4_4_ + -4)) {
        puVar14 = (undefined4 *)*puVar14;
      }
      FUN_1002bbb0(piVar7,puVar14,*(uint *)((int)local_30._4_4_ + -8));
    }
    FUN_10003240((int)local_b0);
    local_14._0_1_ = 4;
    local_b0[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_b0);
    local_40 = 0;
    local_48c = CoInitializeEx((LPVOID)0x0,0);
    if (local_48c < 0) {
      local_490 = &PTR_vftable_10069ab8;
    }
    else {
      local_48c = 0;
      local_490 = &PTR_vftable_10069aa8;
    }
    local_40 = CONCAT44(local_490,local_48c);
    uVar18 = 0;
    local_14._0_1_ = 5;
    HVar8 = CoInitializeSecurity
                      ((PSECURITY_DESCRIPTOR)0x0,-1,(SOLE_AUTHENTICATION_SERVICE *)0x0,(void *)0x0,0
                       ,3,(void *)0x0,0,(void *)0x0);
    if (HVar8 != 0) {
      piVar7 = FUN_100034b0(local_110,4,0x100610f4);
      local_14._0_1_ = 6;
      if (((char)piVar7[0x12] != '\0') &&
         (FUN_100082c0(piVar7,L"initialize_security err="), (char)piVar7[0x12] != '\0')) {
        FUN_10006730(piVar7,HVar8);
      }
      FUN_10003240((int)local_b0);
      local_14._0_1_ = 7;
      local_b0[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_b0);
    }
    local_38 = 0;
    local_14._0_1_ = 8;
    local_60 = 0;
    local_5c = &PTR_vftable_10069aa8;
    uVar19 = 0x1002ac8d;
    piVar7 = (int *)operator_new(0xc);
    local_14._0_1_ = 9;
    local_484 = piVar7;
    if (piVar7 == (int *)0x0) {
      piVar7 = (int *)0x0;
    }
    else {
      piVar7[0] = 0;
      piVar7[1] = 0;
      piVar7[2] = 0;
      piVar7[1] = 0;
      piVar7[2] = 1;
      uVar19 = 0x1002acc7;
      iVar9 = Ordinal_2(L"ROOT\\CIMV2");
      *piVar7 = iVar9;
      if (iVar9 == 0) goto LAB_1002b1b9;
    }
    local_14._0_1_ = 8;
    if (piVar7 == (int *)0x0) goto LAB_1002b1c3;
    local_47d = FUN_1002c520(&local_38,(IID *)*piVar7,uVar18,uVar19,&local_60);
    LOCK();
    piVar1 = piVar7 + 2;
    iVar9 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar9 == 1) {
      if (*piVar7 != 0) {
        Ordinal_6(*piVar7);
        *piVar7 = 0;
      }
      if ((void *)piVar7[1] != (void *)0x0) {
        thunk_FUN_100330ca((void *)piVar7[1]);
        piVar7[1] = 0;
      }
      FUN_1002e346(piVar7);
    }
    uVar17 = local_488;
    if (local_47d == '\0') {
LAB_1002b0c2:
      FUN_10028720(local_494,(undefined4 *)&local_30,&local_60);
      local_488 = uVar17 | 1;
      if (local_494[4] == 0) {
        FUN_10001d40(local_494,(uint *)L"00000000000000000000000000000000",0x20);
      }
      local_14._0_1_ = 0x12;
      if (local_38._4_4_ != (int *)0x0) {
        (**(code **)(*local_38._4_4_ + 8))(local_38._4_4_);
      }
      local_14._0_1_ = 0x13;
      if ((int *)local_38 != (int *)0x0) {
        (**(code **)(*(int *)local_38 + 8))((int *)local_38);
      }
      if ((local_490[1] == DAT_10069aac) && (local_48c == 0)) {
        CoUninitialize();
      }
      if ((int *)local_30 == (int *)0x0) {
LAB_1002b194:
        ExceptionList = local_1c;
        FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
        return;
      }
      FUN_1002b510((int *)local_30,local_30._4_4_);
      pvVar16 = (int *)local_30;
      if (((uint)((((int)local_28 - (int)(int *)local_30) / 0x18) * 0x18) < 0x1000) ||
         (pvVar16 = *(void **)((int)(int *)local_30 + -4),
         (uint)((int)(int *)local_30 + (-4 - (int)pvVar16)) < 0x20)) {
        FUN_1002e346(pvVar16);
        goto LAB_1002b194;
      }
      goto LAB_1002b1d7;
    }
    piVar7 = (int *)FUN_10028cd0(&local_4ac,&local_38);
    local_14._0_1_ = 10;
    if (local_30._4_4_ == local_28) {
      FUN_1002b3f0(&local_30,local_30._4_4_,piVar7);
    }
    else {
      *local_30._4_4_ = 0;
      local_30._4_4_[4] = 0;
      local_30._4_4_[5] = 0;
      iVar9 = piVar7[1];
      iVar4 = piVar7[2];
      iVar5 = piVar7[3];
      *local_30._4_4_ = *piVar7;
      local_30._4_4_[1] = iVar9;
      local_30._4_4_[2] = iVar4;
      local_30._4_4_[3] = iVar5;
      *(undefined8 *)(local_30._4_4_ + 4) = *(undefined8 *)(piVar7 + 4);
      piVar7[4] = 0;
      piVar7[5] = 7;
      *(undefined2 *)piVar7 = 0;
      local_30 = CONCAT44(local_30._4_4_ + 6,(int *)local_30);
    }
    local_14._0_1_ = 8;
    if (7 < uStack_498) {
      puVar13 = local_4ac;
      if ((uStack_498 * 2 + 2 < 0x1000) ||
         (puVar13 = *(undefined **)(local_4ac + -4),
         local_4ac + (-4 - (int)puVar13) < (undefined *)0x20)) {
        FUN_1002e346(puVar13);
        goto LAB_1002adec;
      }
      goto LAB_1002b1cd;
    }
LAB_1002adec:
    piVar7 = FUN_100034b0(local_110,0x10,0x10061564);
    local_14 = CONCAT31(local_14._1_3_,0xb);
    cVar11 = (char)piVar7[0x12];
    if (cVar11 != '\0') {
      FUN_100082c0(piVar7,L"system uuid=");
      cVar11 = (char)piVar7[0x12];
    }
    puVar14 = (undefined4 *)((int)local_30._4_4_ + -0x18);
    if (cVar11 != '\0') {
      if (7 < *(uint *)((int)local_30._4_4_ + -4)) {
        puVar14 = (undefined4 *)*puVar14;
      }
      FUN_1002bbb0(piVar7,puVar14,*(uint *)((int)local_30._4_4_ + -8));
    }
    FUN_10003240((int)local_b0);
    local_14._0_1_ = 0xc;
    local_b0[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_b0);
    local_14 = CONCAT31(local_14._1_3_,8);
    local_47c = (short *)0x0;
    sVar15 = 0x43;
    iVar9 = SHGetKnownFolderPath(&DAT_100522c0,0,0,&local_47c);
    if (iVar9 == 0) {
      if (local_47c != (short *)0x0) {
        psVar12 = local_47c;
        do {
          sVar2 = *psVar12;
          psVar12 = psVar12 + 1;
        } while (sVar2 != 0);
        if ((int)psVar12 - (int)(local_47c + 1) >> 1 != 0) {
          sVar15 = *local_47c;
        }
        goto LAB_1002aeb8;
      }
    }
    else {
LAB_1002aeb8:
      if (local_47c != (short *)0x0) {
        CoTaskMemFree(local_47c);
        local_47c = (short *)0x0;
      }
    }
    FUN_1000c210(local_478,L"get_hdd_sn");
    local_14._0_1_ = 0xd;
    local_58[0] = (wchar_t ***)0x0;
    local_484 = (int *)CONCAT22(0x3a,sVar15);
    local_48 = 0;
    local_44 = 7;
    FUN_10001d40(local_58,&local_484,2);
    local_14._0_1_ = 0xe;
    ppppwVar10 = local_58;
    if (7 < local_44) {
      ppppwVar10 = (wchar_t ****)local_58[0];
    }
    FUN_1002a0e0(&local_4ac,&local_38,(wchar_t *)ppppwVar10);
    local_14._0_1_ = 0xd;
    local_488 = 2;
    if (local_44 < 8) {
LAB_1002af8a:
      local_48 = 0;
      local_44 = 7;
      local_58[0] = (wchar_t ***)((uint)local_58[0] & 0xffff0000);
      FUN_1000c320((int)local_478);
      local_14._0_1_ = 0xf;
      if (local_30._4_4_ == local_28) {
        FUN_1002b3f0(&local_30,local_30._4_4_,(int *)&local_4ac);
      }
      else {
        *local_30._4_4_ = 0;
        *local_30._4_4_ = (int)local_4ac;
        local_30._4_4_[1] = iStack_4a8;
        local_30._4_4_[2] = iStack_4a4;
        local_30._4_4_[3] = iStack_4a0;
        *(ulonglong *)(local_30._4_4_ + 4) = CONCAT44(uStack_498,local_49c);
        local_30 = CONCAT44(local_30._4_4_ + 6,(int *)local_30);
        local_4ac = (undefined *)((uint)local_4ac & 0xffff0000);
        uStack_498 = 7;
      }
      local_14._0_1_ = 8;
      if (7 < uStack_498) {
        puVar13 = local_4ac;
        if ((0xfff < uStack_498 * 2 + 2) &&
           (puVar13 = *(undefined **)(local_4ac + -4),
           (undefined *)0x1f < local_4ac + (-4 - (int)puVar13))) goto LAB_1002b1d7;
        FUN_1002e346(puVar13);
      }
      piVar7 = FUN_100034b0(local_110,0x10,0x10061564);
      local_14 = CONCAT31(local_14._1_3_,0x10);
      cVar11 = (char)piVar7[0x12];
      if (cVar11 != '\0') {
        FUN_100082c0(piVar7,L"hdd sn=");
        cVar11 = (char)piVar7[0x12];
      }
      puVar14 = (undefined4 *)((int)local_30._4_4_ + -0x18);
      if (cVar11 != '\0') {
        if (7 < *(uint *)((int)local_30._4_4_ + -4)) {
          puVar14 = (undefined4 *)*puVar14;
        }
        FUN_1002bbb0(piVar7,puVar14,*(uint *)((int)local_30._4_4_ + -8));
      }
      FUN_10003240((int)local_b0);
      local_14._0_1_ = 0x11;
      local_b0[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_b0);
      local_14._0_1_ = 8;
      uVar17 = 2;
      goto LAB_1002b0c2;
    }
    ppppwVar10 = (wchar_t ****)local_58[0];
    if ((local_44 * 2 + 2 < 0x1000) ||
       (ppppwVar10 = (wchar_t ****)local_58[0][-1],
       (uint)((int)local_58[0] + (-4 - (int)ppppwVar10)) < 0x20)) {
      FUN_1002e346(ppppwVar10);
      goto LAB_1002af8a;
    }
  }
  else {
    puVar13 = local_4ac;
    if ((uStack_498 * 2 + 2 < 0x1000) ||
       (puVar13 = *(undefined **)(local_4ac + -4),
       local_4ac + (-4 - (int)puVar13) < (undefined *)0x20)) {
      FUN_1002e346(puVar13);
      goto LAB_1002ab17;
    }
    local_14._0_1_ = uVar6;
    FUN_10032f7f();
LAB_1002b1b9:
    FUN_1002f620(0x8007000e);
LAB_1002b1c3:
    FUN_1002f620(0x8007000e);
LAB_1002b1cd:
    FUN_10032f7f();
  }
  FUN_10032f7f();
LAB_1002b1d7:
  FUN_10032f7f();
  pcVar3 = (code *)swi(3);
  (*pcVar3)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002b1e0 @ 1002b1e0