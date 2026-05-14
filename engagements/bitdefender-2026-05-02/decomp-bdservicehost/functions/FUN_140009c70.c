void FUN_140009c70(undefined4 *param_1)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  errno_t eVar4;
  UINT UVar5;
  undefined8 *puVar6;
  uint *puVar7;
  LPWSTR ******pppppppWVar8;
  wchar_t *_BufferSizeInWords;
  uint *puVar9;
  uint *puVar10;
  LPCWSTR ******lpValue;
  wchar_t *pwVar11;
  longlong lVar12;
  uint *******pppppppuVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined1 auStack_1b8 [32];
  undefined4 *local_198;
  longlong local_190 [2];
  undefined8 local_180;
  ulonglong local_178;
  longlong local_170 [2];
  undefined8 local_160;
  ulonglong local_158;
  undefined8 local_150;
  undefined8 uStack_148;
  LPCWSTR ******local_130;
  undefined8 uStack_128;
  longlong local_120;
  ulonglong uStack_118;
  longlong local_110 [5];
  wchar_t *local_e8;
  uint *******local_e0;
  undefined8 uStack_d8;
  longlong local_d0;
  ulonglong uStack_c8;
  LPWSTR ******local_c0 [2];
  ulonglong local_b0;
  ulonglong local_a8;
  wchar_t local_a0 [4];
  LPCWSTR ******local_98;
  undefined8 uStack_90;
  longlong local_88;
  ulonglong uStack_80;
  undefined8 local_78;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined8 local_48;
  undefined8 uStack_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_1b8;
  local_e8 = (wchar_t *)0x0;
  local_a0[0] = L'\0';
  local_a0[1] = L'\0';
  local_a0[2] = L'\0';
  local_a0[3] = L'\0';
  pwVar11 = L"PATH";
  _BufferSizeInWords = local_a0;
  local_198 = param_1;
  eVar4 = _wdupenv_s(&local_e8,(size_t *)_BufferSizeInWords,L"PATH");
  if ((eVar4 == 0) && (_BufferSizeInWords = local_e8, local_e8 != (wchar_t *)0x0)) {
    local_58 = 0;
    local_48 = 0;
    uStack_40 = 7;
    pwVar11 = (wchar_t *)0xffffffffffffffff;
    do {
      pwVar11 = (wchar_t *)((longlong)pwVar11 + 1);
    } while (local_e8[(longlong)pwVar11] != L'\0');
    FUN_140010340(&local_58,(undefined8 *)local_e8,(ulonglong)pwVar11);
    FUN_140035ac0(local_e8);
    local_78 = local_58;
    uStack_70 = uStack_50;
    uStack_6c = uStack_4c;
    local_68 = local_48;
    uStack_60 = uStack_40;
    uVar14 = (undefined4)local_58;
    uVar15 = local_58._4_4_;
    uVar16 = (undefined4)local_48;
    uVar17 = local_48._4_4_;
    uVar18 = (undefined4)uStack_40;
    uVar19 = uStack_40._4_4_;
  }
  else {
    local_68 = 0;
    uStack_60 = 7;
    local_78 = 0;
    local_68._0_4_ = 0;
    local_68._4_4_ = 0;
    uStack_60._0_4_ = 7;
    uStack_60._4_4_ = 0;
    local_78._0_4_ = 0;
    local_78._4_4_ = 0;
    uVar14 = (undefined4)local_78;
    uVar15 = local_78._4_4_;
    uVar16 = (undefined4)local_68;
    uVar17 = local_68._4_4_;
    uVar18 = (undefined4)uStack_60;
    uVar19 = uStack_60._4_4_;
  }
  uVar3 = uStack_6c;
  uVar2 = uStack_70;
  local_88 = 0;
  uStack_80 = 7;
  local_98 = (LPCWSTR ******)0x0;
  uStack_148 = 0;
  puVar6 = (undefined8 *)FUN_140009ba0(local_110,_BufferSizeInWords,pwVar11);
  local_150 = 0;
  if (*(char *)(puVar6 + 4) == '\0') {
    local_e0 = (uint *******)0x0;
    uStack_d8 = uStack_148;
    local_d0 = _DAT_14006e180;
    uStack_c8 = _UNK_14006e188;
  }
  else {
    local_e0 = (uint *******)*puVar6;
    uStack_d8 = puVar6[1];
    local_d0 = puVar6[2];
    uStack_c8 = puVar6[3];
    puVar6[2] = 0;
    puVar6[3] = 7;
    *(undefined2 *)puVar6 = 0;
  }
  FUN_14000d470(local_110);
  if (local_d0 == 0) goto LAB_14000a057;
  local_180 = 0;
  local_178 = 7;
  local_190[0] = 0;
  lVar12 = 0;
  FUN_140010340(local_190,(undefined8 *)&DAT_14006aab8,0);
  FUN_1400054f0((uint *)&local_e0,(uint *)local_190,lVar12);
  if (local_178 < 8) {
LAB_140009ed6:
    pppppppuVar13 = (uint *******)&local_e0;
    if (7 < uStack_c8) {
      pppppppuVar13 = local_e0;
    }
    puVar9 = (uint *)((longlong)pppppppuVar13 + local_d0 * 2);
    for (puVar7 = FUN_140005400((uint *)pppppppuVar13,puVar9); puVar7 != puVar9;
        puVar7 = (uint *)((longlong)puVar7 + 2)) {
      if (((short)*puVar7 != 0x5c) && (puVar10 = puVar9, (short)*puVar7 != 0x2f))
      goto LAB_140009f20;
    }
    goto LAB_140009f6c;
  }
  if ((local_178 * 2 + 2 < 0x1000) ||
     ((local_190[0] - *(longlong *)(local_190[0] + -8)) - 8U < 0x20)) {
    FUN_14002f180();
    goto LAB_140009ed6;
  }
  FUN_140035d28();
  goto LAB_14000a28b;
  while (puVar10 = puVar9, puVar7 != puVar9) {
LAB_140009f20:
    puVar9 = (uint *)((longlong)puVar10 + -2);
    if ((*(short *)puVar9 == 0x5c) || (*(short *)puVar9 == 0x2f)) goto joined_r0x000140009f41;
  }
  goto LAB_140009f6c;
  while( true ) {
    puVar10 = (uint *)((longlong)puVar9 + -2);
    if ((*(short *)puVar10 != 0x5c) && (*(short *)puVar10 != 0x2f)) break;
joined_r0x000140009f41:
    puVar9 = puVar10;
    if (puVar7 == puVar9) break;
  }
LAB_140009f6c:
  local_160 = 0;
  local_158 = 7;
  local_170[0] = 0;
  FUN_140010340(local_170,pppppppuVar13,(longlong)puVar9 - (longlong)pppppppuVar13 >> 1);
  FUN_14000e750(&local_130,local_170);
  if (uStack_80 < 8) {
LAB_140009ff5:
    local_98 = local_130;
    uStack_90 = uStack_128;
    local_88 = local_120;
    uStack_80 = uStack_118;
    if (7 < local_158) {
      if ((0xfff < local_158 * 2 + 2) &&
         (0x1f < (local_170[0] - *(longlong *)(local_170[0] + -8)) - 8U)) goto LAB_14000a291;
      FUN_14002f180();
    }
LAB_14000a057:
    local_b0 = 0;
    local_a8 = 7;
    local_c0[0] = (LPWSTR ******)0x0;
    FUN_1400101a0((longlong *)local_c0,0x104,0);
    pppppppWVar8 = (LPWSTR ******)local_c0;
    if (7 < local_a8) {
      pppppppWVar8 = local_c0[0];
    }
    UVar5 = GetSystemDirectoryW((LPWSTR)pppppppWVar8,0x104);
    if (UVar5 < 0x104) {
      if (local_88 != 0) {
        FUN_14000e630(&local_98,(undefined8 *)&DAT_14006ae8c,1);
      }
      pppppppWVar8 = (LPWSTR ******)local_c0;
      if (7 < local_a8) {
        pppppppWVar8 = local_c0[0];
      }
      FUN_14000e630(&local_98,pppppppWVar8,local_b0);
    }
    lpValue = (LPCWSTR ******)&local_98;
    if (7 < uStack_80) {
      lpValue = local_98;
    }
    SetEnvironmentVariableW(L"PATH",(LPCWSTR)lpValue);
    *param_1 = uVar14;
    param_1[1] = uVar15;
    param_1[2] = uVar2;
    param_1[3] = uVar3;
    param_1[4] = uVar16;
    param_1[5] = uVar17;
    param_1[6] = uVar18;
    param_1[7] = uVar19;
    *(undefined1 *)(param_1 + 8) = 1;
    if (7 < local_a8) {
      if ((0xfff < local_a8 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_c0[0] + (-8 - (longlong)local_c0[0][-1]))))
      goto LAB_14000a291;
      FUN_14002f180();
    }
    local_b0 = 0;
    local_a8 = 7;
    local_c0[0] = (LPWSTR ******)((ulonglong)local_c0[0] & 0xffffffffffff0000);
    if (7 < uStack_c8) {
      if ((0xfff < uStack_c8 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_e0 + (-8 - (longlong)local_e0[-1]))))
      goto LAB_14000a297;
      FUN_14002f180();
    }
    local_d0 = 0;
    uStack_c8 = 7;
    local_e0 = (uint *******)((ulonglong)local_e0 & 0xffffffffffff0000);
    if (7 < uStack_80) {
      if ((0xfff < uStack_80 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_98 + (-8 - (longlong)local_98[-1]))))
      goto LAB_14000a29d;
      FUN_14002f180();
    }
    FUN_14002f160(local_38 ^ (ulonglong)auStack_1b8);
    return;
  }
  if ((uStack_80 * 2 + 2 < 0x1000) ||
     ((ulonglong)((longlong)local_98 + (-8 - (longlong)local_98[-1])) < 0x20)) {
    FUN_14002f180();
    goto LAB_140009ff5;
  }
LAB_14000a28b:
  FUN_140035d28();
LAB_14000a291:
  FUN_140035d28();
LAB_14000a297:
  FUN_140035d28();
LAB_14000a29d:
  FUN_140035d28();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000a2b0 @ 14000a2b0