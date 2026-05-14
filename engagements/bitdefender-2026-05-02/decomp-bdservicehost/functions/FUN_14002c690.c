void FUN_14002c690(undefined8 *param_1)

{
  ulonglong uVar1;
  code *pcVar2;
  undefined8 ****ppppuVar3;
  DWORD DVar4;
  SC_HANDLE pSVar5;
  ulonglong uVar6;
  undefined8 ***pppuVar7;
  undefined8 *puVar8;
  wchar_t *pwVar9;
  undefined4 *puVar10;
  uint *puVar11;
  LPCWSTR pWVar12;
  LPCWSTR lpServiceName;
  ulonglong uVar13;
  undefined8 ****ppppuVar14;
  ulonglong uVar15;
  LPCWSTR lpDisplayName;
  LPCWSTR ***lpBinaryPathName;
  WCHAR *pWVar16;
  undefined1 auStackY_188 [32];
  undefined8 local_118;
  undefined8 uStack_110;
  undefined8 local_108;
  undefined8 ***local_100 [2];
  ulonglong local_f0;
  ulonglong local_e8;
  uint local_e0 [14];
  wchar_t *local_a8;
  SC_HANDLE local_a0;
  char local_98;
  SC_HANDLE local_90;
  char local_88;
  LPCWSTR **local_80;
  undefined8 uStack_78;
  undefined8 local_70;
  ulonglong uStack_68;
  SC_HANDLE local_60;
  char local_58;
  WCHAR local_50;
  undefined6 uStack_4e;
  longlong local_40;
  ulonglong local_38;
  ulonglong local_30;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStackY_188;
  pSVar5 = OpenSCManagerW((LPCWSTR)0x0,(LPCWSTR)0x0,0xf003f);
  local_98 = pSVar5 == (SC_HANDLE)0x0;
  if ((bool)local_98) {
    DVar4 = GetLastError();
    local_a0 = (SC_HANDLE)CONCAT44(local_a0._4_4_,DVar4);
    goto LAB_14002cbac;
  }
  local_a0 = pSVar5;
  FUN_1400060a0(&local_50);
  if (local_40 == 0x7ffffffffffffffe) {
    FUN_140001a20();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  pWVar16 = &local_50;
  if (7 < local_38) {
    pWVar16 = (WCHAR *)CONCAT62(uStack_4e,local_50);
  }
  local_100[0] = (undefined8 ****)0x0;
  local_f0 = 0;
  local_e8 = 0;
  uVar1 = local_40 + 1;
  uVar15 = 7;
  uVar13 = 0xffffffffffffffff;
  ppppuVar14 = local_100;
  ppppuVar3 = (undefined8 ****)local_100[0];
  if (uVar1 < 8) {
LAB_14002c7ed:
    local_100[0] = ppppuVar3;
    local_f0 = uVar1;
    local_e8 = uVar15;
    *(undefined2 *)ppppuVar14 = DAT_14006b098;
    FUN_1400316b0((undefined8 *)((longlong)ppppuVar14 + 2),(undefined8 *)pWVar16,local_40 * 2);
    *(undefined2 *)((longlong)ppppuVar14 + uVar1 * 2) = 0;
    puVar8 = FUN_14000e630(local_100,(undefined8 *)&DAT_14006b098,1);
    local_80 = (LPCWSTR **)*puVar8;
    uStack_78 = puVar8[1];
    local_70 = puVar8[2];
    uStack_68 = puVar8[3];
    puVar8[2] = 0;
    puVar8[3] = 7;
    *(undefined2 *)puVar8 = 0;
    if (7 < local_e8) {
      if ((0xfff < local_e8 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_100[0] + (-8 - (longlong)local_100[0][-1]))))
      goto LAB_14002cc00;
      FUN_14002f180();
    }
    local_f0 = 0;
    local_e8 = 7;
    local_100[0] = (undefined8 ***)((ulonglong)local_100[0] & 0xffffffffffff0000);
    FUN_14000e630(&local_80,(undefined8 *)&DAT_14006dea0,2);
    do {
      uVar13 = uVar13 + 1;
    } while (*(short *)((longlong)param_1 + uVar13 * 2) != 0);
    FUN_14000e630(&local_80,param_1,uVar13);
    FUN_14000e630(&local_80,(undefined8 *)&DAT_14006b098,1);
    pWVar12 = DAT_14007acf0 + 0x20;
    if (7 < *(ulonglong *)(DAT_14007acf0 + 0x2c)) {
      pWVar12 = *(LPCWSTR *)pWVar12;
    }
    lpBinaryPathName = &local_80;
    if (7 < uStack_68) {
      lpBinaryPathName = (LPCWSTR ***)local_80;
    }
    lpDisplayName = DAT_14007acf0 + 0x10;
    if (7 < *(ulonglong *)(DAT_14007acf0 + 0x1c)) {
      lpDisplayName = *(LPCWSTR *)lpDisplayName;
    }
    lpServiceName = DAT_14007acf0;
    if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
      lpServiceName = *(LPCWSTR *)DAT_14007acf0;
    }
    if (local_98 == '\0') {
      pSVar5 = CreateServiceW(local_a0,lpServiceName,lpDisplayName,0xf01ff,0x10,4,1,
                              (LPCWSTR)lpBinaryPathName,pWVar12,(LPDWORD)0x0,(LPCWSTR)0x0,
                              (LPCWSTR)0x0,(LPCWSTR)0x0);
      local_58 = pSVar5 == (SC_HANDLE)0x0;
      if ((bool)local_58) {
        DVar4 = GetLastError();
        local_60 = (SC_HANDLE)CONCAT44(local_60._4_4_,DVar4);
        puVar10 = (undefined4 *)FUN_14002d200((longlong)&local_60);
        FUN_14002d250(local_e0,*puVar10);
        puVar8 = (undefined8 *)FUN_14002a6a0((longlong *)local_100,local_e0);
        FUN_140001a40(&local_118,puVar8);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_118,(ThrowInfo *)&DAT_140077818);
      }
      pWVar12 = DAT_14007acf0;
      if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
        pWVar12 = *(LPCWSTR *)DAT_14007acf0;
      }
      local_60 = pSVar5;
      if (local_98 != '\0') {
        local_118 = 0;
        uStack_110 = 0;
        local_108 = 0;
        FUN_14000ec80(&local_118);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_118,(ThrowInfo *)&DAT_1400777e0);
      }
      pSVar5 = OpenServiceW(local_a0,pWVar12,2);
      local_88 = pSVar5 == (SC_HANDLE)0x0;
      if ((bool)local_88) {
        DVar4 = GetLastError();
        local_90 = (SC_HANDLE)CONCAT44(local_90._4_4_,DVar4);
        puVar10 = (undefined4 *)FUN_14002d200((longlong)&local_90);
        puVar11 = FUN_14002d300(local_e0,*puVar10,(undefined8 *)"open_service failed");
        puVar8 = (undefined8 *)FUN_14002a6a0((longlong *)local_100,puVar11);
        FUN_140001a40(&local_118,puVar8);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_118,(ThrowInfo *)&DAT_140077818);
      }
      pwVar9 = DAT_14007acf0 + 0x30;
      if (7 < *(ulonglong *)(DAT_14007acf0 + 0x3c)) {
        pwVar9 = *(wchar_t **)pwVar9;
      }
      local_90 = pSVar5;
      pwVar9 = _wcsdup(pwVar9);
      local_a8 = pwVar9;
      ChangeServiceConfig2W(pSVar5,1,&local_a8);
      if (pwVar9 != (wchar_t *)0x0) {
        FUN_140035ac0(pwVar9);
      }
      if ((char)DAT_14007acf0[0x74] != '\0') {
        FUN_14002c3f0();
        if (local_88 != '\0') {
          local_118 = 0;
          uStack_110 = 0;
          local_108 = 0;
          FUN_14000ec80(&local_118);
                    /* WARNING: Subroutine does not return */
          _CxxThrowException(&local_118,(ThrowInfo *)&DAT_1400777e0);
        }
        FUN_14002bba0((undefined8 *)local_e0,local_90,3);
        FUN_14002d150((longlong)local_e0);
      }
      if (((local_88 != -1) && (local_88 == '\0')) && (local_90 != (SC_HANDLE)0x0)) {
        CloseServiceHandle(local_90);
      }
      if (((local_58 != -1) && (local_58 == '\0')) && (local_60 != (SC_HANDLE)0x0)) {
        CloseServiceHandle(local_60);
      }
      if (7 < uStack_68) {
        if ((0xfff < uStack_68 * 2 + 2) &&
           (0x1f < (ulonglong)((longlong)local_80 + (-8 - (longlong)local_80[-1])))) {
          FUN_140035d28();
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        FUN_14002f180();
      }
      local_70 = 0;
      uStack_68 = 7;
      local_80 = (LPCWSTR **)((ulonglong)local_80 & 0xffffffffffff0000);
      if (7 < local_38) {
        if ((0xfff < local_38 * 2 + 2) &&
           (0x1f < (CONCAT62(uStack_4e,local_50) - *(longlong *)(CONCAT62(uStack_4e,local_50) + -8))
                   - 8U)) {
          FUN_140035d28();
LAB_14002cbac:
          puVar10 = (undefined4 *)FUN_14002d200((longlong)&local_a0);
          puVar11 = FUN_14002d300(local_e0,*puVar10,(undefined8 *)"open_sc_manager failed");
          puVar8 = (undefined8 *)FUN_14002a6a0((longlong *)local_100,puVar11);
          FUN_140001a40(&local_118,puVar8);
                    /* WARNING: Subroutine does not return */
          _CxxThrowException(&local_118,(ThrowInfo *)&DAT_140077818);
        }
        FUN_14002f180();
      }
      local_40 = 0;
      local_38 = 7;
      local_50 = L'\0';
      if (((local_98 != -1) && (local_98 == '\0')) && (local_a0 != (SC_HANDLE)0x0)) {
        CloseServiceHandle(local_a0);
      }
      FUN_14002f160(local_30 ^ (ulonglong)auStackY_188);
      return;
    }
  }
  else {
    uVar15 = uVar1;
    if (uVar1 < 8) {
      uVar15 = DAT_14006b8f0;
    }
    uVar15 = uVar15 | 7;
    if (uVar15 < 0x7fffffffffffffff) {
      if (uVar15 < 10) {
        uVar15 = 10;
      }
    }
    else {
      uVar15 = 0x7ffffffffffffffe;
    }
    uVar6 = uVar15 + 1;
    if (uVar15 == 0xffffffffffffffff) {
      uVar6 = uVar13;
    }
    if (uVar6 < 0x8000000000000000) {
      uVar6 = uVar6 * 2;
      if (uVar6 < 0x1000) {
        ppppuVar14 = (undefined8 ****)0x0;
        ppppuVar3 = (undefined8 ****)0x0;
        if (uVar6 != 0) {
          ppppuVar14 = (undefined8 ****)operator_new(uVar6);
          ppppuVar3 = ppppuVar14;
        }
        goto LAB_14002c7ed;
      }
      if (uVar6 + 0x27 <= uVar6) goto LAB_14002cc06;
      pppuVar7 = (undefined8 ***)operator_new(uVar6 + 0x27);
      if (pppuVar7 != (undefined8 ***)0x0) {
        ppppuVar14 = (undefined8 ****)((longlong)pppuVar7 + 0x27U & 0xffffffffffffffe0);
        ppppuVar14[-1] = pppuVar7;
        ppppuVar3 = ppppuVar14;
        goto LAB_14002c7ed;
      }
      FUN_140035d28();
LAB_14002cc00:
      FUN_140035d28();
    }
LAB_14002cc06:
    FUN_140001670();
  }
  local_118 = 0;
  uStack_110 = 0;
  local_108 = 0;
  FUN_14000ec80(&local_118);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(&local_118,(ThrowInfo *)&DAT_1400777e0);
}


// FUNCTION_END

// FUNCTION_START: FUN_14002cd20 @ 14002cd20

/* WARNING: Removing unreachable block (ram,0x00014002cfa4) */