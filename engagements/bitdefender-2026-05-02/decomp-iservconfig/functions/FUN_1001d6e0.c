void __fastcall FUN_1001d6e0(LPCWSTR param_1,int param_2,LPCWSTR param_3)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined1 uVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  LPCSTR pCVar10;
  short ****ppppsVar11;
  undefined4 extraout_ECX;
  void *pvVar12;
  undefined4 extraout_ECX_00;
  undefined4 in_stack_fffffeb8;
  undefined4 uVar13;
  undefined1 local_128 [24];
  undefined1 local_110 [24];
  undefined1 local_f8 [24];
  undefined1 local_e0 [8];
  undefined8 local_d8;
  undefined1 *local_d0;
  undefined1 local_cc;
  void *local_c8 [4];
  undefined4 local_b8;
  uint local_b4;
  void *local_b0 [4];
  undefined4 local_a0;
  uint local_9c;
  undefined1 local_98 [8];
  undefined8 local_90;
  undefined1 *local_88;
  undefined1 local_84;
  undefined1 local_80 [8];
  undefined8 local_78;
  undefined1 local_6c;
  undefined1 local_68 [4];
  int local_64;
  char local_60 [16];
  short ***local_50 [4];
  undefined4 local_40;
  uint local_3c;
  undefined8 local_38;
  undefined1 local_2d;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14._0_1_ = 0xff;
  local_14._1_3_ = 0xffffff;
  puStack_18 = &LAB_1004f980;
  local_1c = ExceptionList;
  uVar7 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = &stack0xfffffec8;
  ExceptionList = &local_1c;
  local_64 = param_2;
  local_2c = uVar7;
  puVar5 = &stack0xfffffffc;
  puVar6 = &stack0xfffffec8;
  if (param_3 == (LPCWSTR)0x0) goto LAB_1001da57;
  FUN_10023550(local_f8);
  local_14 = 0;
  puVar8 = (undefined4 *)FUN_1001c850(local_b0,param_1);
  local_14._0_1_ = 1;
  local_d8 = 0;
  local_e0[0] = 3;
  puVar9 = (undefined4 *)operator_new(0x18);
  *puVar9 = 0;
  puVar9[4] = 0;
  puVar9[5] = 0;
  uVar13 = puVar8[1];
  uVar2 = puVar8[2];
  uVar3 = puVar8[3];
  *puVar9 = *puVar8;
  puVar9[1] = uVar13;
  puVar9[2] = uVar2;
  puVar9[3] = uVar3;
  *(undefined8 *)(puVar9 + 4) = *(undefined8 *)(puVar8 + 4);
  puVar8[4] = 0;
  puVar8[5] = 0xf;
  *(undefined1 *)puVar8 = 0;
  local_d0 = local_e0;
  local_d8 = CONCAT44(local_38._4_4_,puVar9);
  local_cc = 1;
  local_14._0_1_ = 3;
  FUN_10021b30(local_128,local_f8,local_c8);
  local_14._0_1_ = 4;
  local_90 = 0;
  local_98[0] = 3;
  local_38 = 0;
  puVar8 = (undefined4 *)operator_new(0x18);
  local_38 = CONCAT44(puVar8,&local_2d);
  local_14._0_1_ = 5;
  *puVar8 = 0;
  puVar8[4] = 0;
  puVar8[5] = 0xf;
  FUN_10008e70(puVar8,(uint *)&DAT_1005fdb8,3);
  local_88 = local_98;
  local_90 = CONCAT44(local_90._4_4_,puVar8);
  local_84 = 1;
  local_80[0] = 0;
  local_78 = 0;
  FUN_10024400(local_80,local_64);
  local_6c = 1;
  local_14._0_1_ = 6;
  uVar13 = 0x1001d88a;
  FUN_10021b30(local_110,local_98,local_68);
  local_14._0_1_ = 8;
  FUN_10021de0(local_60,in_stack_fffffeb8,uVar13,local_128,local_f8);
  local_14._0_1_ = 10;
  _eh_vector_destructor_iterator_(local_128,0x18,2,thunk_FUN_1000e760);
  local_14._0_1_ = 0xb;
  _eh_vector_destructor_iterator_(local_98,0x18,2,thunk_FUN_1000e760);
  local_14._0_1_ = 0xc;
  _eh_vector_destructor_iterator_(local_f8,0x18,2,thunk_FUN_1000e760);
  local_14._0_1_ = 0xd;
  uVar4 = (undefined1)local_14;
  local_14._0_1_ = 0xd;
  if (local_9c < 0x10) {
LAB_1001d930:
    local_a0 = 0;
    local_9c = 0xf;
    local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
    local_14._0_1_ = 0xe;
    pCVar10 = (LPCSTR)FUN_10021b60(local_60,local_c8);
    if (0xf < *(uint *)(pCVar10 + 0x14)) {
      pCVar10 = *(LPCSTR *)pCVar10;
    }
    FUN_1001c8a0(local_50,pCVar10,uVar7);
    local_14._0_1_ = 0xf;
    uVar13 = extraout_ECX;
    if (0xf < local_b4) {
      pvVar12 = local_c8[0];
      if ((0xfff < local_b4 + 1) &&
         (pvVar12 = *(void **)((int)local_c8[0] + -4),
         0x1f < (uint)((int)local_c8[0] + (-4 - (int)pvVar12)))) goto LAB_1001da7a;
      FUN_1002e346(pvVar12);
      uVar13 = extraout_ECX_00;
    }
    local_b8 = 0;
    ppppsVar11 = local_50;
    if (7 < local_3c) {
      ppppsVar11 = (short ****)local_50[0];
    }
    local_b4 = 0xf;
    local_c8[0] = (void *)((uint)local_c8[0] & 0xffffff00);
    local_2d = FUN_10026e10(uVar13,param_3,L"lang",(short *)ppppsVar11);
    if (7 < local_3c) {
      ppppsVar11 = (short ****)local_50[0];
      if ((0xfff < local_3c * 2 + 2) &&
         (ppppsVar11 = (short ****)local_50[0][-1],
         0x1f < (uint)((int)local_50[0] + (-4 - (int)ppppsVar11)))) goto LAB_1001da7f;
      FUN_1002e346(ppppsVar11);
    }
    local_40 = 0;
    local_3c = 7;
    local_50[0] = (short ***)((uint)local_50[0] & 0xffff0000);
    FUN_1000e760(local_60);
    puVar5 = puStack_24;
    puVar6 = local_20;
LAB_1001da57:
    local_20 = puVar6;
    puStack_24 = puVar5;
    ExceptionList = local_1c;
    FUN_1002e315(local_2c ^ (uint)&stack0xfffffff0);
    return;
  }
  pvVar12 = local_b0[0];
  if ((local_9c + 1 < 0x1000) ||
     (pvVar12 = *(void **)((int)local_b0[0] + -4),
     (uint)((int)local_b0[0] + (-4 - (int)pvVar12)) < 0x20)) {
    FUN_1002e346(pvVar12);
    goto LAB_1001d930;
  }
  local_14._0_1_ = uVar4;
  FUN_10032f7f();
LAB_1001da7a:
  FUN_10032f7f();
LAB_1001da7f:
  FUN_10032f7f();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@1001da41 @ 1001da41