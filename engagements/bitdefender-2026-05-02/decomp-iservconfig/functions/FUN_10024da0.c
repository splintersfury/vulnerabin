void FUN_10024da0(void *param_1)

{
  code *pcVar1;
  char cVar2;
  uint uVar3;
  void *extraout_ECX;
  void *pvVar4;
  void *this;
  LPCSTR ***ppppCVar5;
  void *local_1a4;
  undefined4 uStack_1a0;
  undefined4 uStack_19c;
  undefined4 uStack_198;
  undefined4 local_194;
  uint uStack_190;
  undefined1 local_189;
  LPCSTR **local_188 [5];
  uint local_174;
  LPCSTR **local_170 [5];
  uint local_15c;
  LPCSTR **local_158 [5];
  uint local_144;
  LPCSTR **local_140 [5];
  uint local_12c;
  LPCSTR **local_128 [5];
  uint local_114;
  LPCSTR **local_110 [5];
  uint local_fc;
  LPCSTR **local_f8 [5];
  uint local_e4;
  undefined2 local_e0;
  LPCSTR **local_dc [5];
  uint local_c8;
  char local_c4;
  LPCSTR **local_c0 [5];
  uint local_ac;
  char local_a8;
  LPCSTR **local_a4 [5];
  uint local_90;
  char local_8c;
  LPCSTR **local_88 [5];
  uint local_74;
  LPCSTR **local_70 [5];
  uint local_5c;
  char local_58;
  LPCSTR **local_54 [5];
  uint local_40;
  char local_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_100501f0;
  local_1c = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_24 = uVar3;
  FUN_100255b0(local_188);
  local_14 = 0;
  cVar2 = FUN_10024a70(this,extraout_ECX);
  if (cVar2 == '\0') {
    local_189 = 0;
  }
  else {
    ppppCVar5 = local_128;
    if (0xf < local_114) {
      ppppCVar5 = (LPCSTR ***)local_128[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380((void *)((int)param_1 + 0x60),(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    ppppCVar5 = local_188;
    if (0xf < local_174) {
      ppppCVar5 = (LPCSTR ***)local_188[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380(param_1,(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    ppppCVar5 = local_158;
    if (0xf < local_144) {
      ppppCVar5 = (LPCSTR ***)local_158[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380((void *)((int)param_1 + 0x30),(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    ppppCVar5 = local_140;
    if (0xf < local_12c) {
      ppppCVar5 = (LPCSTR ***)local_140[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380((void *)((int)param_1 + 0x48),(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    ppppCVar5 = local_170;
    if (0xf < local_15c) {
      ppppCVar5 = (LPCSTR ***)local_170[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380((void *)((int)param_1 + 0x18),(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    ppppCVar5 = local_110;
    if (0xf < local_fc) {
      ppppCVar5 = (LPCSTR ***)local_110[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380((void *)((int)param_1 + 0x78),(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    ppppCVar5 = local_f8;
    if (0xf < local_e4) {
      ppppCVar5 = (LPCSTR ***)local_f8[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380((void *)((int)param_1 + 0x90),(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    *(undefined2 *)((int)param_1 + 0xa8) = local_e0;
    if (local_c4 == '\0') {
      FUN_10026ac0((int *)((int)param_1 + 0xac));
    }
    else {
      ppppCVar5 = local_dc;
      if (0xf < local_c8) {
        ppppCVar5 = (LPCSTR ***)local_dc[0];
      }
      FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
      if (*(char *)((int)param_1 + 0xc4) == '\0') {
        *(undefined4 *)((int)param_1 + 0xbc) = 0;
        *(undefined4 *)((int)param_1 + 0xc0) = 0;
        *(undefined4 *)((int)param_1 + 0xac) = local_1a4;
        *(undefined4 *)((int)param_1 + 0xb0) = uStack_1a0;
        *(undefined4 *)((int)param_1 + 0xb4) = uStack_19c;
        *(undefined4 *)((int)param_1 + 0xb8) = uStack_198;
        *(ulonglong *)((int)param_1 + 0xbc) = CONCAT44(uStack_190,local_194);
        *(undefined1 *)((int)param_1 + 0xc4) = 1;
      }
      else {
        FUN_10005380((undefined4 *)((int)param_1 + 0xac),(int *)&local_1a4);
        if (7 < uStack_190) {
          pvVar4 = local_1a4;
          if (0xfff < uStack_190 * 2 + 2) {
            pvVar4 = *(void **)((int)local_1a4 + -4);
            if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
          }
          FUN_1002e346(pvVar4);
        }
      }
    }
    if (local_a8 == '\0') {
      FUN_10026ac0((int *)((int)param_1 + 200));
    }
    else {
      ppppCVar5 = local_c0;
      if (0xf < local_ac) {
        ppppCVar5 = (LPCSTR ***)local_c0[0];
      }
      FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
      if (*(char *)((int)param_1 + 0xe0) == '\0') {
        *(undefined4 *)((int)param_1 + 0xd8) = 0;
        *(undefined4 *)((int)param_1 + 0xdc) = 0;
        *(undefined4 *)((int)param_1 + 200) = local_1a4;
        *(undefined4 *)((int)param_1 + 0xcc) = uStack_1a0;
        *(undefined4 *)((int)param_1 + 0xd0) = uStack_19c;
        *(undefined4 *)((int)param_1 + 0xd4) = uStack_198;
        *(ulonglong *)((int)param_1 + 0xd8) = CONCAT44(uStack_190,local_194);
        *(undefined1 *)((int)param_1 + 0xe0) = 1;
      }
      else {
        FUN_10005380((undefined4 *)((int)param_1 + 200),(int *)&local_1a4);
        if (7 < uStack_190) {
          pvVar4 = local_1a4;
          if (0xfff < uStack_190 * 2 + 2) {
            pvVar4 = *(void **)((int)local_1a4 + -4);
            if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
          }
          FUN_1002e346(pvVar4);
        }
      }
    }
    if (local_8c == '\0') {
      FUN_10026ac0((int *)((int)param_1 + 0xe4));
    }
    else {
      ppppCVar5 = local_a4;
      if (0xf < local_90) {
        ppppCVar5 = (LPCSTR ***)local_a4[0];
      }
      FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
      if (*(char *)((int)param_1 + 0xfc) == '\0') {
        *(undefined4 *)((int)param_1 + 0xf4) = 0;
        *(undefined4 *)((int)param_1 + 0xf8) = 0;
        *(undefined4 *)((int)param_1 + 0xe4) = local_1a4;
        *(undefined4 *)((int)param_1 + 0xe8) = uStack_1a0;
        *(undefined4 *)((int)param_1 + 0xec) = uStack_19c;
        *(undefined4 *)((int)param_1 + 0xf0) = uStack_198;
        *(ulonglong *)((int)param_1 + 0xf4) = CONCAT44(uStack_190,local_194);
        *(undefined1 *)((int)param_1 + 0xfc) = 1;
      }
      else {
        FUN_10005380((undefined4 *)((int)param_1 + 0xe4),(int *)&local_1a4);
        if (7 < uStack_190) {
          pvVar4 = local_1a4;
          if (0xfff < uStack_190 * 2 + 2) {
            pvVar4 = *(void **)((int)local_1a4 + -4);
            if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
          }
          FUN_1002e346(pvVar4);
        }
      }
    }
    ppppCVar5 = local_88;
    if (0xf < local_74) {
      ppppCVar5 = (LPCSTR ***)local_88[0];
    }
    FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
    FUN_10005380((void *)((int)param_1 + 0x100),(int *)&local_1a4);
    if (7 < uStack_190) {
      pvVar4 = local_1a4;
      if (0xfff < uStack_190 * 2 + 2) {
        pvVar4 = *(void **)((int)local_1a4 + -4);
        if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
      }
      FUN_1002e346(pvVar4);
    }
    if (local_58 == '\0') {
      FUN_10026ac0((int *)((int)param_1 + 0x118));
    }
    else {
      ppppCVar5 = local_70;
      if (0xf < local_5c) {
        ppppCVar5 = (LPCSTR ***)local_70[0];
      }
      FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
      if (*(char *)((int)param_1 + 0x130) == '\0') {
        *(undefined4 *)((int)param_1 + 0x128) = 0;
        *(undefined4 *)((int)param_1 + 300) = 0;
        *(undefined4 *)((int)param_1 + 0x118) = local_1a4;
        *(undefined4 *)((int)param_1 + 0x11c) = uStack_1a0;
        *(undefined4 *)((int)param_1 + 0x120) = uStack_19c;
        *(undefined4 *)((int)param_1 + 0x124) = uStack_198;
        *(ulonglong *)((int)param_1 + 0x128) = CONCAT44(uStack_190,local_194);
        *(undefined1 *)((int)param_1 + 0x130) = 1;
      }
      else {
        FUN_10005380((undefined4 *)((int)param_1 + 0x118),(int *)&local_1a4);
        if (7 < uStack_190) {
          pvVar4 = local_1a4;
          if (0xfff < uStack_190 * 2 + 2) {
            pvVar4 = *(void **)((int)local_1a4 + -4);
            if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) goto LAB_1002559b;
          }
          FUN_1002e346(pvVar4);
        }
      }
    }
    if (local_3c == '\0') {
      FUN_10026ac0((int *)((int)param_1 + 0x134));
    }
    else {
      ppppCVar5 = local_54;
      if (0xf < local_40) {
        ppppCVar5 = (LPCSTR ***)local_54[0];
      }
      FUN_1001c8a0(&local_1a4,(LPCSTR)ppppCVar5,uVar3);
      if (*(char *)((int)param_1 + 0x14c) == '\0') {
        *(undefined4 *)((int)param_1 + 0x144) = 0;
        *(undefined4 *)((int)param_1 + 0x148) = 0;
        *(undefined4 *)((int)param_1 + 0x134) = local_1a4;
        *(undefined4 *)((int)param_1 + 0x138) = uStack_1a0;
        *(undefined4 *)((int)param_1 + 0x13c) = uStack_19c;
        *(undefined4 *)((int)param_1 + 0x140) = uStack_198;
        *(ulonglong *)((int)param_1 + 0x144) = CONCAT44(uStack_190,local_194);
        *(undefined1 *)((int)param_1 + 0x14c) = 1;
      }
      else {
        FUN_10005380((undefined4 *)((int)param_1 + 0x134),(int *)&local_1a4);
        if (7 < uStack_190) {
          pvVar4 = local_1a4;
          if (0xfff < uStack_190 * 2 + 2) {
            pvVar4 = *(void **)((int)local_1a4 + -4);
            if (0x1f < (uint)((int)local_1a4 + (-4 - (int)pvVar4))) {
LAB_1002559b:
              FUN_10032f7f();
              pcVar1 = (code *)swi(3);
              (*pcVar1)();
              return;
            }
          }
          FUN_1002e346(pvVar4);
        }
      }
    }
    local_189 = 1;
    *(undefined4 *)((int)param_1 + 0x150) = local_38;
    *(undefined4 *)((int)param_1 + 0x154) = uStack_34;
    *(undefined4 *)((int)param_1 + 0x158) = uStack_30;
    *(undefined4 *)((int)param_1 + 0x15c) = uStack_2c;
  }
  FUN_100256b0((int *)local_188);
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100255b0 @ 100255b0