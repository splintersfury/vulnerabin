void __fastcall FUN_1001cec0(undefined4 *param_1,LPCWSTR param_2)

{
  int iVar1;
  LPCWSTR **pppWVar2;
  char cVar3;
  uint uVar4;
  uint ****ppppuVar5;
  undefined4 *puVar6;
  int *piVar7;
  undefined4 uVar8;
  double *pdVar9;
  byte *pbVar10;
  char *pcVar11;
  uint *puVar12;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  void *pvVar13;
  LPCWSTR ***ppppWVar14;
  int local_e8 [7];
  undefined4 local_cc;
  int *local_c8;
  undefined4 *local_c4;
  void *local_c0 [4];
  undefined4 local_b0;
  uint local_ac;
  void *local_a8 [2];
  undefined4 local_a0;
  undefined4 uStack_9c;
  undefined4 uStack_98;
  uint uStack_94;
  char local_90 [8];
  void *local_88;
  uint ***local_7c [2];
  undefined4 local_74 [2];
  uint local_6c;
  uint local_68;
  LPCWSTR **local_64 [4];
  undefined4 local_54;
  uint local_50;
  undefined4 *local_4c;
  LPCWSTR **local_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  uint local_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004f8ce;
  local_1c = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = &stack0xffffff08;
  ExceptionList = &local_1c;
  local_38 = 0;
  uStack_34 = 7;
  local_48 = (LPCWSTR **)0x0;
  local_c4 = param_1;
  local_4c = param_1;
  local_2c = uVar4;
  FUN_10001d40(&local_48,(uint *)L"en-US",5);
  local_30 = 0;
  local_14 = 0;
  if (param_2 == (LPCWSTR)0x0) {
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    *param_1 = local_48;
    param_1[1] = uStack_44;
    param_1[2] = uStack_40;
    param_1[3] = uStack_3c;
    *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_34,local_38);
    param_1[6] = 0;
    goto LAB_1001d63e;
  }
  local_54 = 0;
  local_50 = 7;
  local_64[0] = (LPCWSTR **)0x0;
  local_14._0_1_ = 1;
  local_14._1_3_ = 0;
  cVar3 = FUN_10026b80((HKEY)0x80000002,param_2,L"lang",local_64);
  if (cVar3 == '\0') {
    local_6c = 0;
    local_68 = 7;
    local_7c[0] = (uint ***)0x0;
    local_14 = CONCAT31(local_14._1_3_,2);
    cVar3 = FUN_10026b80((HKEY)0x80000003,L".DEFAULT\\Software\\SetID",L"wslibsite_lang",local_7c);
    uVar8 = extraout_ECX;
    if (cVar3 != '\0') {
      ppppuVar5 = local_7c;
      if (7 < local_68) {
        ppppuVar5 = (uint ****)local_7c[0];
      }
      FUN_10001d40(&local_48,(uint *)ppppuVar5,local_6c);
      uVar8 = extraout_ECX_00;
    }
    cVar3 = FUN_10027320(uVar8,(LPBYTE)&local_4c);
    if (cVar3 != '\0') {
      local_30 = (uint)(local_4c != (undefined4 *)0x0);
    }
    ppppWVar14 = &local_48;
    if (7 < uStack_34) {
      ppppWVar14 = (LPCWSTR ***)local_48;
    }
    FUN_1001d6e0((LPCWSTR)ppppWVar14,local_30,param_2);
    pppWVar2 = local_48;
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    local_48 = (LPCWSTR **)((uint)local_48 & 0xffff0000);
    *param_1 = pppWVar2;
    param_1[1] = uStack_44;
    param_1[2] = uStack_40;
    param_1[3] = uStack_3c;
    *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_34,local_38);
    local_38 = 0;
    uStack_34 = 7;
    param_1[6] = local_30;
    if (local_68 < 8) {
LAB_1001d0b5:
      if (7 < local_50) {
        ppppWVar14 = (LPCWSTR ***)local_64[0];
        if ((0xfff < local_50 * 2 + 2) &&
           (ppppWVar14 = (LPCWSTR ***)local_64[0][-1],
           0x1f < (uint)((int)local_64[0] + (-4 - (int)ppppWVar14)))) goto LAB_1001d65e;
        FUN_1002e346(ppppWVar14);
      }
      local_54 = 0;
      local_50 = 7;
      local_64[0] = (LPCWSTR **)((uint)local_64[0] & 0xffff0000);
      if (uStack_34 < 8) goto LAB_1001d63e;
      ppppWVar14 = (LPCWSTR ***)local_48;
      if ((uStack_34 * 2 + 2 < 0x1000) ||
         (ppppWVar14 = (LPCWSTR ***)local_48[-1],
         (uint)((int)local_48 + (-4 - (int)ppppWVar14)) < 0x20)) goto LAB_1001d634;
    }
    else {
      ppppuVar5 = (uint ****)local_7c[0];
      if ((local_68 * 2 + 2 < 0x1000) ||
         (ppppuVar5 = (uint ****)local_7c[0][-1],
         (uint)((int)local_7c[0] + (-4 - (int)ppppuVar5)) < 0x20)) {
        FUN_1002e346(ppppuVar5);
        goto LAB_1001d0b5;
      }
    }
LAB_1001d65e:
    FUN_10032f7f();
LAB_1001d663:
    FUN_10032f7f();
  }
  else {
    ppppWVar14 = local_64;
    if (7 < local_50) {
      ppppWVar14 = (LPCWSTR ***)local_64[0];
    }
    FUN_1001c850(local_c0,(LPCWSTR)ppppWVar14);
    local_14._0_1_ = 4;
    FUN_10014700(&local_cc,local_c0);
    local_14._0_1_ = 5;
    FUN_1000f810(local_90,&local_cc,1);
    local_14 = CONCAT31(local_14._1_3_,7);
    if (local_c8 != (int *)0x0) {
      LOCK();
      iVar1 = local_c8[1] + -1;
      local_c8[1] = iVar1;
      UNLOCK();
      if (iVar1 == 0) {
        (**(code **)*local_c8)();
        LOCK();
        iVar1 = local_c8[2] + -1;
        local_c8[2] = iVar1;
        UNLOCK();
        if (iVar1 == 0) {
          (**(code **)(*local_c8 + 4))();
        }
      }
    }
    if (local_90[0] != '\x01') {
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 0;
      *param_1 = local_48;
      param_1[1] = uStack_44;
      param_1[2] = uStack_40;
      param_1[3] = uStack_3c;
      local_48 = (LPCWSTR **)((uint)local_48 & 0xffff0000);
      *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_34,local_38);
      local_38 = 0;
      uStack_34 = 7;
      param_1[6] = local_30;
      FUN_1000e760(local_90);
      if (local_ac < 0x10) {
LAB_1001d249:
        local_b0 = 0;
        local_ac = 0xf;
        local_c0[0] = (void *)((uint)local_c0[0] & 0xffffff00);
        if (7 < local_50) {
          ppppWVar14 = (LPCWSTR ***)local_64[0];
          if ((0xfff < local_50 * 2 + 2) &&
             (ppppWVar14 = (LPCWSTR ***)local_64[0][-1],
             0x1f < (uint)((int)local_64[0] + (-4 - (int)ppppWVar14)))) goto LAB_1001d663;
          FUN_1002e346(ppppWVar14);
        }
        local_54 = 0;
        local_50 = 7;
        local_64[0] = (LPCWSTR **)((uint)local_64[0] & 0xffff0000);
        if (uStack_34 < 8) goto LAB_1001d63e;
        ppppWVar14 = (LPCWSTR ***)local_48;
        if ((0xfff < uStack_34 * 2 + 2) &&
           (ppppWVar14 = (LPCWSTR ***)local_48[-1],
           0x1f < (uint)((int)local_48 + (-4 - (int)ppppWVar14)))) goto LAB_1001d663;
LAB_1001d634:
        local_50 = 7;
        local_54 = 0;
        FUN_1002e346(ppppWVar14);
LAB_1001d63e:
        ExceptionList = local_1c;
        FUN_1002e315(local_2c ^ (uint)&stack0xfffffff0);
        return;
      }
      pvVar13 = local_c0[0];
      if ((local_ac + 1 < 0x1000) ||
         (pvVar13 = *(void **)((int)local_c0[0] + -4),
         (uint)((int)local_c0[0] + (-4 - (int)pvVar13)) < 0x20)) {
        FUN_1002e346(pvVar13);
        goto LAB_1001d249;
      }
      goto LAB_1001d663;
    }
    local_a0 = 0;
    uStack_9c = 0;
    uStack_98 = 0;
    uStack_94 = 0;
    FUN_100184e0(local_90,&local_a0);
    if (local_90[0] == '\x01') {
      puVar6 = (undefined4 *)FUN_10023d80(local_88,(int *)&local_c4,&DAT_1005fdb0);
      uStack_9c = *puVar6;
    }
    piVar7 = FUN_100184e0(local_90,local_74);
    uVar8 = FUN_10018200(&local_a0,piVar7);
    if (((char)uVar8 == '\0') || (pcVar11 = FUN_100182c0(&local_a0), *pcVar11 != '\x03')) {
LAB_1001d410:
      local_a0 = 0;
      uStack_9c = 0;
      uStack_98 = 0;
      uStack_94 = 0;
      FUN_100184e0(local_90,&local_a0);
      if (local_90[0] == '\x01') {
        puVar6 = (undefined4 *)FUN_10023d80(local_88,(int *)&local_c4,&DAT_1005fdb8);
        uStack_9c = *puVar6;
      }
      piVar7 = FUN_100184e0(local_90,local_74);
      uVar8 = FUN_10018200(&local_a0,piVar7);
      if ((char)uVar8 != '\0') {
        pcVar11 = FUN_100182c0(&local_a0);
        if ((*pcVar11 != '\x05') && (*pcVar11 != '\x06')) goto LAB_1001d4f8;
        pcVar11 = FUN_100182c0(&local_a0);
        cVar3 = *pcVar11;
        switch(cVar3) {
        case '\x04':
          pbVar10 = (byte *)(pcVar11 + 8);
          if (cVar3 != '\x04') {
            pbVar10 = (byte *)0x0;
          }
          local_30 = (uint)*pbVar10;
          break;
        case '\x05':
          if ((cVar3 == '\x05') || (local_30 = uRam00000000, cVar3 == '\x06')) {
            local_30 = *(uint *)(pcVar11 + 8);
          }
          break;
        case '\x06':
          puVar12 = (uint *)(pcVar11 + 8);
          if (cVar3 != '\x06') {
            puVar12 = (uint *)0x0;
          }
          local_30 = *puVar12;
          break;
        case '\a':
          pdVar9 = (double *)(pcVar11 + 8);
          if (cVar3 != '\a') {
            pdVar9 = (double *)0x0;
          }
          local_30 = (int)*pdVar9;
          break;
        default:
          goto switchD_1001d49c_caseD_4;
        }
        if ((local_30 == 0) || (local_30 == 1)) {
          FUN_1000e760(local_90);
          FUN_1001d51e();
          return;
        }
        local_30 = 0;
      }
LAB_1001d4f8:
      FUN_1000e760(local_90);
      FUN_1001d51e();
      return;
    }
    pcVar11 = FUN_100182c0(&local_a0);
    FUN_100142f0(pcVar11,(uint *)local_7c);
    if (local_6c == 0) {
LAB_1001d3dc:
      if (0xf < local_68) {
        ppppuVar5 = (uint ****)local_7c[0];
        if ((0xfff < local_68 + 1) &&
           (ppppuVar5 = (uint ****)local_7c[0][-1],
           0x1f < (uint)((int)local_7c[0] + (-4 - (int)ppppuVar5)))) goto LAB_1001d668;
        FUN_1002e346(ppppuVar5);
      }
      goto LAB_1001d410;
    }
    ppppuVar5 = local_7c;
    if (0xf < local_68) {
      ppppuVar5 = (uint ****)local_7c[0];
    }
    FUN_1001c8a0(local_a8,(LPCSTR)ppppuVar5,uVar4);
    FUN_10005380(&local_48,(int *)local_a8);
    if (uStack_94 < 8) goto LAB_1001d3dc;
    pvVar13 = local_a8[0];
    if ((uStack_94 * 2 + 2 < 0x1000) ||
       (pvVar13 = *(void **)((int)local_a8[0] + -4),
       (uint)((int)local_a8[0] + (-4 - (int)pvVar13)) < 0x20)) {
      FUN_1002e346(pvVar13);
      goto LAB_1001d3dc;
    }
  }
LAB_1001d668:
  pcVar11 = (char *)FUN_10032f7f();
switchD_1001d49c_caseD_4:
  puVar12 = (uint *)FUN_1000f7b0(pcVar11);
  puVar12 = FUN_10005690(local_7c,puVar12);
  local_14._0_1_ = 8;
  puVar12 = FUN_10005f20((uint *)local_a8,(uint *)"type must be number, but is ",puVar12);
  local_14 = CONCAT31(local_14._1_3_,9);
  FUN_1000ad90(local_e8,0x12e,puVar12);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_e8,&DAT_10067608);
}


// FUNCTION_END

// FUNCTION_START: Catch@1001d50f @ 1001d50f