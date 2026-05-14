void FUN_140009410(HMODULE param_1,undefined8 *param_2,undefined8 param_3)

{
  code *pcVar1;
  bool bVar2;
  bool bVar3;
  char cVar4;
  DWORD DVar5;
  DWORD DVar6;
  uint *puVar7;
  short *psVar8;
  HMODULE *ppHVar9;
  HMODULE pHVar10;
  HMODULE pHVar11;
  LPCWSTR ****pppppWVar12;
  LPCWSTR pWVar13;
  ulonglong uVar14;
  longlong lVar15;
  undefined **ppuVar16;
  undefined1 auStack_118 [32];
  HMODULE local_f8;
  HMODULE local_f0;
  undefined4 local_e8;
  HMODULE local_e0 [3];
  ulonglong local_c8;
  HMODULE local_b8;
  undefined **ppuStack_b0;
  HMODULE local_a8;
  undefined **ppuStack_a0;
  undefined8 local_98;
  ulonglong local_90;
  undefined8 local_88;
  undefined8 local_78;
  ulonglong uStack_70;
  LPCWSTR ***local_68 [3];
  ulonglong local_50;
  HMODULE local_48;
  ulonglong local_40;
  
  local_40 = DAT_14007a060 ^ (ulonglong)auStack_118;
  DVar6 = 0;
  local_e8 = 0;
  local_b8 = (HMODULE)0x0;
  ppuVar16 = &PTR_vftable_14007ac70;
  ppuStack_b0 = &PTR_vftable_14007ac70;
  local_f8 = param_1;
  FUN_140006180((longlong *)&local_a8,&local_b8,param_3);
  if ((ppuStack_b0[1] == DAT_14007ac78) && ((DWORD)local_b8 == 0)) {
    pHVar10 = (HMODULE)&local_a8;
    if (7 < local_90) {
      pHVar10 = local_a8;
    }
    cVar4 = FUN_140005250((LPCWSTR)pHVar10,(DWORD *)&local_b8);
    if (local_90 < 8) goto LAB_14000951f;
    if ((local_90 * 2 + 2 < 0x1000) ||
       ((ulonglong)((longlong)local_a8 + (-8 - *(longlong *)(local_a8 + -2))) < 0x20)) {
      FUN_14002f180();
      goto LAB_14000951f;
    }
LAB_140009af9:
    FUN_140035d28();
LAB_140009aff:
    FUN_140035d28();
LAB_140009b05:
    FUN_140035d28();
LAB_140009b0b:
    FUN_140035d28();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (7 < local_90) {
    if ((0xfff < local_90 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_a8 + (-8 - *(longlong *)(local_a8 + -2)))))
    goto LAB_140009af9;
    FUN_14002f180();
  }
  cVar4 = '\0';
LAB_14000951f:
  local_b8 = (HMODULE)0x0;
  ppuStack_b0 = &PTR_vftable_14007ac70;
  local_98 = 0;
  local_90 = 7;
  local_a8 = (HMODULE)0x0;
  lVar15 = 7;
  FUN_140010340((longlong *)&local_a8,(undefined8 *)L"log.dll",7);
  FUN_14000e750(local_e0,param_2);
  puVar7 = FUN_1400054f0((uint *)local_e0,(uint *)&local_a8,lVar15);
  pHVar10 = (HMODULE)local_68;
  FUN_14000e750((undefined8 *)pHVar10,(undefined8 *)puVar7);
  if (7 < local_c8) {
    pHVar10 = local_e0[0];
    if ((0xfff < local_c8 * 2 + 2) &&
       (pHVar10 = *(HMODULE *)(local_e0[0] + -2),
       0x1f < (ulonglong)((longlong)local_e0[0] + (-8 - (longlong)pHVar10)))) goto LAB_140009aff;
    FUN_14002f180();
  }
  uVar14 = local_90;
  if (7 < local_90) {
    uVar14 = local_90 * 2 + 2;
    pHVar10 = local_a8;
    if (0xfff < uVar14) {
      uVar14 = local_90 * 2 + 0x29;
      pHVar10 = *(HMODULE *)(local_a8 + -2);
      if (0x1f < (ulonglong)((longlong)local_a8 + (-8 - (longlong)pHVar10))) goto LAB_140009b05;
    }
    FUN_14002f180();
  }
  if (cVar4 == '\0') {
    pppppWVar12 = local_68;
    if (7 < local_50) {
      pppppWVar12 = (LPCWSTR ****)local_68[0];
    }
    pHVar10 = LoadLibraryW((LPCWSTR)pppppWVar12);
    if (pHVar10 == (HMODULE)0x0) {
      DVar5 = GetLastError();
      local_a8 = (HMODULE)CONCAT44(local_a8._4_4_,DVar5);
      ppuStack_a0 = &PTR_vftable_14007ad08;
      local_b8 = local_a8;
      ppuStack_b0 = &PTR_vftable_14007ad08;
    }
    ppHVar9 = &local_f8;
    bVar3 = false;
    bVar2 = true;
  }
  else {
    psVar8 = (short *)FUN_140006460(pHVar10,uVar14,lVar15);
    if (7 < *(ulonglong *)(psVar8 + 0xc)) {
      psVar8 = *(short **)psVar8;
    }
    pppppWVar12 = local_68;
    if (7 < local_50) {
      pppppWVar12 = (LPCWSTR ****)local_68[0];
    }
    ppHVar9 = (HMODULE *)FUN_140005f40(&local_f0,(LPCWSTR)pppppWVar12,psVar8,&local_b8);
    bVar3 = true;
    bVar2 = false;
    pHVar10 = *ppHVar9;
  }
  local_48 = pHVar10;
  *ppHVar9 = (HMODULE)0x0;
  if ((bVar2) && (local_f8 != (HMODULE)0x0)) {
    FreeLibrary(local_f8);
  }
  if ((bVar3) && (local_f0 != (HMODULE)0x0)) {
    FreeLibrary(local_f0);
    local_f0 = (HMODULE)0x0;
  }
  if ((ppuStack_b0[1] == DAT_14007ac78) && ((DWORD)local_b8 == 0)) {
    local_98 = 0;
    local_90 = 7;
    local_a8 = (HMODULE)0x0;
    psVar8 = (short *)0xf;
    FUN_140010340((longlong *)&local_a8,(undefined8 *)L"iservconfig.dll",0xf);
    FUN_14000e750(local_e0,param_2);
    puVar7 = FUN_1400054f0((uint *)local_e0,(uint *)&local_a8,(longlong)psVar8);
    pHVar11 = (HMODULE)&local_88;
    FUN_14000e750((undefined8 *)pHVar11,(undefined8 *)puVar7);
    if (7 < local_c8) {
      pHVar11 = local_e0[0];
      if ((0xfff < local_c8 * 2 + 2) &&
         (pHVar11 = *(HMODULE *)(local_e0[0] + -2),
         0x1f < (ulonglong)((longlong)local_e0[0] + (-8 - (longlong)pHVar11)))) goto LAB_140009b0b;
      FUN_14002f180();
    }
    uVar14 = local_90;
    if (7 < local_90) {
      uVar14 = local_90 * 2 + 2;
      pHVar11 = local_a8;
      if (uVar14 < 0x1000) {
LAB_1400097ab:
        FUN_14002f180();
        goto LAB_1400097b0;
      }
      uVar14 = local_90 * 2 + 0x29;
      pHVar11 = *(HMODULE *)(local_a8 + -2);
      if ((ulonglong)((longlong)local_a8 + (-8 - (longlong)pHVar11)) < 0x20) goto LAB_1400097ab;
      FUN_140035d28();
LAB_140009aed:
      FUN_140035d28();
      goto LAB_140009af3;
    }
LAB_1400097b0:
    if (cVar4 == '\0') {
      pWVar13 = (LPCWSTR)&local_88;
      if (7 < uStack_70) {
        pWVar13 = (LPCWSTR)CONCAT62(local_88._2_6_,(WCHAR)local_88);
      }
      pHVar11 = LoadLibraryW(pWVar13);
      if (pHVar11 == (HMODULE)0x0) {
        DVar6 = GetLastError();
        local_a8 = (HMODULE)CONCAT44(local_a8._4_4_,DVar6);
        ppuStack_a0 = &PTR_vftable_14007ad08;
        ppuStack_b0 = &PTR_vftable_14007ad08;
        ppuVar16 = &PTR_vftable_14007ad08;
      }
      ppHVar9 = &local_f0;
      bVar3 = false;
      bVar2 = true;
    }
    else {
      psVar8 = (short *)FUN_140006460(pHVar11,uVar14,psVar8);
      if (7 < *(ulonglong *)(psVar8 + 0xc)) {
        psVar8 = *(short **)psVar8;
      }
      pWVar13 = (LPCWSTR)&local_88;
      if (7 < uStack_70) {
        pWVar13 = (LPCWSTR)CONCAT62(local_88._2_6_,(WCHAR)local_88);
      }
      ppHVar9 = (HMODULE *)FUN_140005f40(&local_f8,pWVar13,psVar8,&local_b8);
      pHVar11 = *ppHVar9;
      bVar3 = true;
      bVar2 = false;
      ppuVar16 = ppuStack_b0;
      DVar6 = (DWORD)local_b8;
    }
    local_b8 = pHVar11;
    *ppHVar9 = (HMODULE)0x0;
    if ((bVar2) && (local_f0 != (HMODULE)0x0)) {
      FreeLibrary(local_f0);
    }
    if ((bVar3) && (local_f8 != (HMODULE)0x0)) {
      FreeLibrary(local_f8);
      local_f8 = (HMODULE)0x0;
    }
    if ((ppuVar16[1] == DAT_14007ac78) && (DVar6 == 0)) {
      local_f0 = (HMODULE)((ulonglong)local_f0 & 0xffffffff00000000);
      local_a8 = (HMODULE)0x0;
      ppuStack_a0 = (undefined **)0x0;
      pWVar13 = (LPCWSTR)&local_88;
      if (7 < uStack_70) {
        pWVar13 = (LPCWSTR)CONCAT62(local_88._2_6_,(WCHAR)local_88);
      }
      FUN_140012520((longlong *)&local_a8,pWVar13,psVar8,(DWORD *)&local_f0);
      if (ppuStack_a0 == (undefined **)0x0) {
        *(undefined1 *)&param_1[8].unused = 0;
        if (local_a8 != (HMODULE)0x0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)(local_a8,1);
        }
        if (pHVar11 != (HMODULE)0x0) {
          FreeLibrary(pHVar11);
        }
        if (uStack_70 < 8) goto LAB_14000993d;
        if ((uStack_70 * 2 + 2 < 0x1000) ||
           ((CONCAT62(local_88._2_6_,(WCHAR)local_88) -
            *(longlong *)(CONCAT62(local_88._2_6_,(WCHAR)local_88) + -8)) - 8U < 0x20))
        goto LAB_140009938;
        goto LAB_140009aed;
      }
      *(HMODULE *)param_1 = pHVar10;
      *(HMODULE *)(param_1 + 2) = pHVar11;
      *(HMODULE *)(param_1 + 4) = local_a8;
      *(undefined ***)(param_1 + 6) = ppuStack_a0;
      *(undefined1 *)&param_1[8].unused = 1;
      if (7 < uStack_70) {
        if ((0xfff < uStack_70 * 2 + 2) &&
           (0x1f < (CONCAT62(local_88._2_6_,(WCHAR)local_88) -
                   *(longlong *)(CONCAT62(local_88._2_6_,(WCHAR)local_88) + -8)) - 8U))
        goto LAB_140009aed;
        FUN_14002f180();
      }
      local_78 = _DAT_14006e180;
      uStack_70 = _UNK_14006e188;
      local_88._0_2_ = L'\0';
    }
    else {
      *(undefined1 *)&param_1[8].unused = 0;
      if (pHVar11 != (HMODULE)0x0) {
        FreeLibrary(pHVar11);
      }
      if (7 < uStack_70) {
        if ((0xfff < uStack_70 * 2 + 2) &&
           (0x1f < (CONCAT62(local_88._2_6_,(WCHAR)local_88) -
                   *(longlong *)(CONCAT62(local_88._2_6_,(WCHAR)local_88) + -8)) - 8U))
        goto LAB_140009aed;
LAB_140009938:
        FUN_14002f180();
      }
LAB_14000993d:
      local_88._0_2_ = L'\0';
      local_78 = _DAT_14006e180;
      uStack_70 = _UNK_14006e188;
      if (pHVar10 != (HMODULE)0x0) {
        FreeLibrary(pHVar10);
      }
    }
    if (local_50 < 8) goto LAB_14000999e;
    if (0xfff < local_50 * 2 + 2) {
      uVar14 = (longlong)local_68[0] + (-8 - (longlong)local_68[0][-1]);
      goto joined_r0x000140009ae0;
    }
  }
  else {
    *(undefined1 *)&param_1[8].unused = 0;
    if (pHVar10 != (HMODULE)0x0) {
      FreeLibrary(pHVar10);
    }
    if (local_50 < 8) goto LAB_14000999e;
    if (0xfff < local_50 * 2 + 2) {
      uVar14 = (longlong)local_68[0] + (-8 - (longlong)local_68[0][-1]);
joined_r0x000140009ae0:
      if (0x1f < uVar14) {
LAB_140009af3:
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
  }
  FUN_14002f180();
LAB_14000999e:
  FUN_14002f160(local_40 ^ (ulonglong)auStack_118);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140009b30 @ 140009b30