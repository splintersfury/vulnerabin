void FUN_1400042c0(undefined8 *param_1,PCCERT_CONTEXT param_2,int *param_3)

{
  code *pcVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  undefined **ppuVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  ulonglong *puVar11;
  int *piVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined1 auStackY_128 [32];
  undefined8 in_stack_fffffffffffffef8;
  undefined4 local_f8;
  undefined4 uStack_f4;
  undefined **ppuStack_f0;
  ulonglong local_e8;
  ulonglong uStack_e0;
  undefined8 local_d8;
  undefined4 uStack_d0;
  undefined4 uStack_cc;
  ulonglong local_c8;
  ulonglong uStack_c0;
  ulonglong local_b8;
  undefined **ppuStack_b0;
  ulonglong local_a8;
  ulonglong uStack_a0;
  ulonglong local_98;
  undefined **ppuStack_90;
  ulonglong local_88;
  ulonglong uStack_80;
  ulonglong local_78;
  
  uVar14 = _UNK_14006e188;
  uVar13 = _DAT_14006e180;
  local_78 = DAT_14007a060 ^ (ulonglong)auStackY_128;
  if (param_2->pCertInfo == (PCERT_INFO)0x0) {
    local_f8 = 0xd;
    ppuStack_f0 = &PTR_vftable_14007ad08;
    *(ulonglong *)param_3 = CONCAT44(uStack_f4,0xd);
    *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ad08;
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    param_1[4] = 0;
    param_1[6] = 0;
    param_1[7] = 7;
    param_1[8] = 0;
    param_1[10] = 0;
    param_1[0xb] = 7;
    goto LAB_14000452d;
  }
  local_d8 = 0;
  local_c8 = _DAT_14006e180;
  uStack_c0 = _UNK_14006e188;
  local_b8 = 0;
  local_a8 = _DAT_14006e180;
  uStack_a0 = _UNK_14006e188;
  local_98 = 0;
  local_88 = _DAT_14006e180;
  uStack_80 = _UNK_14006e188;
  piVar12 = param_3;
  puVar11 = (ulonglong *)FUN_140003ef0((longlong *)&local_f8,(longlong)param_2->pCertInfo,param_3);
  if (&local_d8 == puVar11) {
    uVar15 = (undefined4)local_d8;
    uVar16 = local_d8._4_4_;
  }
  else {
    uVar3 = *puVar11;
    local_d8 = *puVar11;
    uStack_d0 = (undefined4)puVar11[1];
    uStack_cc = *(undefined4 *)((longlong)puVar11 + 0xc);
    uVar13 = puVar11[2];
    uVar14 = puVar11[3];
    puVar11[2] = 0;
    puVar11[3] = 7;
    *(undefined2 *)puVar11 = 0;
    uVar15 = (int)uVar3;
    uVar16 = *(undefined4 *)((longlong)puVar11 + 4);
    local_c8 = uVar13;
    uStack_c0 = uVar14;
  }
  uVar10 = uStack_cc;
  uVar9 = uStack_d0;
  if (7 < uStack_e0) {
    if ((0xfff < uStack_e0 * 2 + 2) &&
       (0x1f < (CONCAT44(uStack_f4,local_f8) - *(longlong *)(CONCAT44(uStack_f4,local_f8) + -8)) -
               8U)) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  if ((*(longlong *)(*(longlong *)(param_3 + 2) + 8) != DAT_14007ac78) || (*param_3 != 0)) {
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    param_1[4] = 0;
    param_1[6] = 0;
    param_1[7] = 7;
    param_1[8] = 0;
    param_1[10] = 0;
    param_1[0xb] = 7;
    FUN_1400039f0(&local_d8);
    goto LAB_14000452d;
  }
  FUN_140003ba0((undefined8 *)&local_f8,param_2,piVar12,1,in_stack_fffffffffffffef8,param_3);
  uVar8 = uStack_e0;
  uVar7 = local_e8;
  ppuVar6 = ppuStack_f0;
  uVar3 = CONCAT44(uStack_f4,local_f8);
  ppuStack_b0 = ppuStack_f0;
  local_a8 = local_e8;
  uStack_a0 = uStack_e0;
  local_b8 = uVar3;
  if ((*(longlong *)(*(longlong *)(param_3 + 2) + 8) == DAT_14007ac78) && (*param_3 == 0)) {
    FUN_140003ba0((undefined8 *)&local_f8,param_2,piVar12,0,in_stack_fffffffffffffef8,param_3);
    uVar5 = _UNK_14006e188;
    uVar4 = _DAT_14006e180;
    uVar2 = CONCAT44(uStack_f4,local_f8);
    ppuStack_90 = ppuStack_f0;
    local_88 = local_e8;
    uStack_80 = uStack_e0;
    local_98 = uVar2;
    if ((*(longlong *)(*(longlong *)(param_3 + 2) + 8) != DAT_14007ac78) || (*param_3 != 0))
    goto LAB_14000454a;
    *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ac70;
    *param_3 = 0;
    *(undefined4 *)param_1 = uVar15;
    *(undefined4 *)((longlong)param_1 + 4) = uVar16;
    *(undefined4 *)(param_1 + 1) = uVar9;
    *(undefined4 *)((longlong)param_1 + 0xc) = uVar10;
    local_d8 = local_d8 & 0xffffffffffff0000;
    param_1[2] = uVar13;
    param_1[3] = uVar14;
    local_b8 = local_b8 & 0xffffffffffff0000;
    param_1[4] = uVar3;
    param_1[5] = ppuVar6;
    local_98 = uVar2 & 0xffffffffffff0000;
    param_1[6] = uVar7;
    param_1[7] = uVar8;
    param_1[8] = uVar2;
    param_1[9] = ppuStack_f0;
    param_1[10] = local_e8;
    param_1[0xb] = uStack_e0;
    local_c8 = uVar4;
    uStack_c0 = uVar5;
    local_a8 = uVar4;
    uStack_a0 = uVar5;
    local_88 = uVar4;
    uStack_80 = uVar5;
  }
  else {
LAB_14000454a:
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    param_1[4] = 0;
    param_1[6] = 0;
    param_1[7] = 7;
    param_1[8] = 0;
    param_1[10] = 0;
    param_1[0xb] = 7;
  }
  FUN_1400039f0(&local_d8);
LAB_14000452d:
  FUN_14002f160(local_78 ^ (ulonglong)auStackY_128);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400045c0 @ 1400045c0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */