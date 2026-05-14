void FUN_14001b450(longlong *param_1,longlong *param_2,undefined8 param_3,LPCSTR ***param_4)

{
  longlong lVar1;
  code *pcVar2;
  undefined1 uVar3;
  undefined4 uVar4;
  BOOL BVar5;
  longlong *plVar6;
  longlong *plVar7;
  undefined8 uVar8;
  DWORDLONG dwlConditionMask;
  char ****ppppcVar9;
  ulonglong uVar10;
  LPCSTR **pppCVar11;
  undefined1 auStack_1f8 [32];
  undefined1 local_1d8 [8];
  LPCSTR *local_1d0 [2];
  undefined8 local_1c0;
  ulonglong local_1b8;
  undefined4 local_1b0;
  undefined8 local_1a8 [2];
  undefined8 local_198;
  ulonglong local_190;
  char local_168 [8];
  longlong *local_160;
  _OSVERSIONINFOEXW local_158;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_1f8;
  local_1b0 = 0;
  FUN_14001de50(local_168,'\0');
  ppppcVar9 = (char ****)local_168;
  FUN_14001cbe0(param_2,ppppcVar9,param_3,param_4);
  FUN_140019eb0(local_168,ppppcVar9,param_3,param_4);
  local_1c0 = 0;
  local_1b8 = 0xf;
  local_1d0[0] = (LPCSTR *)0x0;
  FUN_1400106a0((longlong *)local_1d0,(undefined8 *)"serviceName",0xb);
  plVar6 = FUN_14001a110(local_1a8,local_168,local_1d0,param_4);
  FUN_14000e6b0(param_1,plVar6);
  if (local_190 < 8) {
LAB_14001b53c:
    local_198 = 0;
    local_190 = 7;
    local_1a8[0]._0_2_ = 0;
    if (0xf < local_1b8) {
      if ((local_1b8 + 1 < 0x1000) ||
         ((ulonglong)((longlong)local_1d0[0] + (-8 - (longlong)local_1d0[0][-1])) < 0x20)) {
        FUN_14002f180();
        goto LAB_14001b58d;
      }
      goto LAB_14001bba9;
    }
LAB_14001b58d:
    local_1c0 = 0;
    local_1b8 = 0xf;
    local_1d0[0] = (LPCSTR *)0x0;
    FUN_1400106a0((longlong *)local_1d0,(undefined8 *)"serviceDisplayName",0x12);
    plVar6 = FUN_14001a110(local_1a8,local_168,local_1d0,param_4);
    FUN_14000e6b0(param_1 + 4,plVar6);
    if (7 < local_190) {
      if ((local_190 * 2 + 2 < 0x1000) ||
         ((CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) -
          *(longlong *)(CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_14001b61e;
      }
      goto LAB_14001bbaf;
    }
LAB_14001b61e:
    local_198 = 0;
    local_190 = 7;
    local_1a8[0]._0_2_ = 0;
    if (0xf < local_1b8) {
      if ((local_1b8 + 1 < 0x1000) ||
         ((ulonglong)((longlong)local_1d0[0] + (-8 - (longlong)local_1d0[0][-1])) < 0x20)) {
        FUN_14002f180();
        goto LAB_14001b66f;
      }
      goto LAB_14001bbb5;
    }
LAB_14001b66f:
    local_1c0 = 0;
    local_1b8 = 0xf;
    local_1d0[0] = (LPCSTR *)0x0;
    FUN_1400106a0((longlong *)local_1d0,(undefined8 *)"serviceGroup",0xc);
    plVar6 = FUN_14001a110(local_1a8,local_168,local_1d0,param_4);
    FUN_14000e6b0(param_1 + 8,plVar6);
    if (7 < local_190) {
      if ((local_190 * 2 + 2 < 0x1000) ||
         ((CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) -
          *(longlong *)(CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_14001b700;
      }
      goto LAB_14001bbbb;
    }
LAB_14001b700:
    local_198 = 0;
    local_190 = 7;
    local_1a8[0]._0_2_ = 0;
    if (0xf < local_1b8) {
      if ((local_1b8 + 1 < 0x1000) ||
         ((ulonglong)((longlong)local_1d0[0] + (-8 - (longlong)local_1d0[0][-1])) < 0x20)) {
        FUN_14002f180();
        goto LAB_14001b751;
      }
      goto LAB_14001bbc1;
    }
LAB_14001b751:
    local_1c0 = 0;
    local_1b8 = 0xf;
    local_1d0[0] = (LPCSTR *)0x0;
    FUN_1400106a0((longlong *)local_1d0,(undefined8 *)"serviceDescription",0x12);
    plVar6 = FUN_14001a110(local_1a8,local_168,local_1d0,param_4);
    FUN_14000e6b0(param_1 + 0xc,plVar6);
    if (7 < local_190) {
      if ((local_190 * 2 + 2 < 0x1000) ||
         ((CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) -
          *(longlong *)(CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) + -8)) - 8U < 0x20)) {
        FUN_14002f180();
        goto LAB_14001b7e2;
      }
      goto LAB_14001bbc7;
    }
LAB_14001b7e2:
    local_198 = 0;
    local_190 = 7;
    local_1a8[0]._0_2_ = 0;
    if (0xf < local_1b8) {
      if ((local_1b8 + 1 < 0x1000) ||
         ((ulonglong)((longlong)local_1d0[0] + (-8 - (longlong)local_1d0[0][-1])) < 0x20)) {
        FUN_14002f180();
        goto LAB_14001b833;
      }
      goto LAB_14001bbcd;
    }
LAB_14001b833:
    local_1c0 = 0;
    local_1b8 = 0xf;
    local_1d0[0] = (LPCSTR *)0x0;
    FUN_1400106a0((longlong *)local_1d0,(undefined8 *)"relativeDllPath",0xf);
    pppCVar11 = local_1d0;
    plVar6 = FUN_14001a110(local_1a8,local_168,pppCVar11,param_4);
    FUN_14000e6b0(param_1 + 0x10,plVar6);
    if (local_190 < 8) {
LAB_14001b8c7:
      local_198 = 0;
      local_190 = 7;
      local_1a8[0]._0_2_ = 0;
      uVar10 = local_1b8;
      if (0xf < local_1b8) {
        uVar10 = local_1b8 + 1;
        if ((0xfff < uVar10) &&
           (uVar10 = local_1b8 + 0x28,
           0x1f < (ulonglong)((longlong)local_1d0[0] + (-8 - (longlong)local_1d0[0][-1]))))
        goto LAB_14001bbd9;
        FUN_14002f180();
      }
      uVar4 = FUN_14001a250(local_168,uVar10,pppCVar11,(ulonglong)param_4);
      *(undefined4 *)(param_1 + 0x14) = uVar4;
      plVar7 = (longlong *)FUN_14001a7f0((float *)local_1a8,(byte *)local_168);
      plVar6 = param_1 + 0x15;
      if (plVar6 != plVar7) {
        FUN_140017620((longlong)plVar6);
        *(int *)plVar6 = (int)*plVar7;
        lVar1 = param_1[0x16];
        param_1[0x16] = plVar7[1];
        plVar7[1] = lVar1;
        lVar1 = param_1[0x17];
        param_1[0x17] = plVar7[2];
        plVar7[2] = lVar1;
        lVar1 = param_1[0x18];
        param_1[0x18] = plVar7[3];
        plVar7[3] = lVar1;
        lVar1 = param_1[0x19];
        param_1[0x19] = plVar7[4];
        plVar7[4] = lVar1;
        lVar1 = param_1[0x1a];
        param_1[0x1a] = plVar7[5];
        plVar7[5] = lVar1;
        lVar1 = param_1[0x1b];
        param_1[0x1b] = plVar7[6];
        plVar7[6] = lVar1;
        lVar1 = param_1[0x1c];
        param_1[0x1c] = plVar7[7];
        plVar7[7] = lVar1;
      }
      FUN_140010a90((longlong)local_1a8);
      local_158.dwOSVersionInfoSize = 0x11c;
      local_158.dwBuildNumber = 0;
      local_158.dwPlatformId = 0;
      FUN_140031e00((undefined1 (*) [16])local_158.szCSDVersion,0,0x100);
      local_158.wServicePackMinor = 0;
      local_158.wSuiteMask = 0;
      local_158.wProductType = '\0';
      local_158.wReserved = '\0';
      uVar8 = VerSetConditionMask(0,2,3);
      uVar8 = VerSetConditionMask(uVar8,1,3);
      dwlConditionMask = VerSetConditionMask(uVar8,0x20,3);
      local_158.dwMajorVersion = 10;
      local_158.dwMinorVersion = 0;
      local_158.wServicePackMajor = 0;
      BVar5 = VerifyVersionInfoW(&local_158,0x23,dwlConditionMask);
      if (BVar5 == 0) {
        uVar3 = 0;
      }
      else {
        local_1c0 = 0;
        local_1b8 = 0xf;
        local_1d0[0] = (LPCSTR *)0x0;
        FUN_1400106a0((longlong *)local_1d0,(undefined8 *)"runProtected",0xc);
        local_1b0 = 1;
        local_1d8[0] = 0;
        uVar3 = FUN_140021b50(local_168,local_1d0,local_1d8);
      }
      *(undefined1 *)(param_1 + 0x1d) = uVar3;
      if ((BVar5 != 0) && (0xf < local_1b8)) {
        if ((0xfff < local_1b8 + 1) &&
           (0x1f < (ulonglong)((longlong)local_1d0[0] + (-8 - (longlong)local_1d0[0][-1])))) {
          FUN_140035d28();
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        FUN_14002f180();
      }
      if (local_168[0] == 1) {
        FUN_140025800(local_160);
      }
      else if (local_168[0] == 2) {
        FUN_140025b90(local_160);
      }
      else {
        if (local_168[0] != 3) goto LAB_14001bb77;
        if (0xf < (ulonglong)local_160[3]) {
          if ((0xfff < local_160[3] + 1U) &&
             (0x1f < (*local_160 - *(longlong *)(*local_160 + -8)) - 8U)) {
            FUN_140035d28();
            goto LAB_14001bba3;
          }
          FUN_14002f180();
        }
        local_160[2] = 0;
        local_160[3] = 0xf;
        *(undefined1 *)local_160 = 0;
      }
      FUN_14002f180();
LAB_14001bb77:
      FUN_14002f160(local_38 ^ (ulonglong)auStack_1f8);
      return;
    }
    if ((local_190 * 2 + 2 < 0x1000) ||
       ((CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) -
        *(longlong *)(CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) + -8)) - 8U < 0x20)) {
      FUN_14002f180();
      goto LAB_14001b8c7;
    }
  }
  else {
    if ((local_190 * 2 + 2 < 0x1000) ||
       ((CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) -
        *(longlong *)(CONCAT62(local_1a8[0]._2_6_,(undefined2)local_1a8[0]) + -8)) - 8U < 0x20)) {
      FUN_14002f180();
      goto LAB_14001b53c;
    }
LAB_14001bba3:
    FUN_140035d28();
LAB_14001bba9:
    FUN_140035d28();
LAB_14001bbaf:
    FUN_140035d28();
LAB_14001bbb5:
    FUN_140035d28();
LAB_14001bbbb:
    FUN_140035d28();
LAB_14001bbc1:
    FUN_140035d28();
LAB_14001bbc7:
    FUN_140035d28();
LAB_14001bbcd:
    FUN_140035d28();
  }
  FUN_140035d28();
LAB_14001bbd9:
  FUN_140035d28();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001bbf0 @ 14001bbf0