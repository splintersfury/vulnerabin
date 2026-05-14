void FUN_1001e130(void)

{
  short sVar1;
  code *pcVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  uint ****ppppuVar7;
  uint ****ppppuVar8;
  LPCSTR ***ppppCVar9;
  ushort *puVar10;
  void *pvVar11;
  uint in_stack_fffffe98;
  uint in_stack_fffffe9c;
  uint in_stack_fffffea0;
  undefined4 uVar12;
  undefined4 uVar13;
  void *in_stack_fffffeac;
  uint in_stack_fffffeb0;
  uint in_stack_fffffeb4;
  uint in_stack_fffffeb8;
  undefined4 in_stack_fffffebc;
  undefined4 in_stack_fffffec0;
  uint *in_stack_fffffec4;
  uint local_cc [13];
  int local_98 [6];
  LPCSTR **local_80 [5];
  uint local_6c;
  int local_68 [4];
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_40;
  undefined4 local_3c;
  undefined *local_38;
  undefined1 *local_34;
  undefined1 *local_30;
  uint ***local_2c [4];
  int local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004fabc;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_38 = &DAT_1006b660;
  local_14 = uVar3;
  iVar4 = __Mtx_lock((_Mtx_internal_imp_t *)&DAT_1006b660);
  if (iVar4 != 0) {
    FUN_1002d2dd(iVar4);
    goto LAB_1001e39b;
  }
  local_8 = iVar4;
  if (*(int *)(*(int *)((int)ThreadLocalStoragePointer + _tls_index * 4) + 4) < DAT_1006b6bc) {
    FUN_1002ec60(&DAT_1006b6bc);
    if (DAT_1006b6bc == -1) {
      local_8._0_1_ = 1;
      _memset(&DAT_1006b6c0,0,0x70);
      FUN_1001e510();
      _atexit((_func_4879 *)&LAB_10050fa0);
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_1002ec16(&DAT_1006b6bc);
    }
  }
  piVar5 = (int *)FUN_1000bdf0(local_cc,&DAT_1006b690);
  local_58 = 0;
  local_54 = 0xf;
  local_68[0] = 0;
  local_40 = 0;
  local_3c = 0xf;
  local_50 = 0;
  piVar6 = local_68;
  if ((char)piVar5[0xc] == '\0') {
    piVar6 = piVar5;
  }
  FUN_10017630(local_98,piVar6);
  ppppCVar9 = local_80;
  if (0xf < local_6c) {
    ppppCVar9 = (LPCSTR ***)local_80[0];
  }
  FUN_1001c8a0(local_2c,(LPCSTR)ppppCVar9,uVar3);
  FUN_1000bb10(local_98);
  FUN_1000bb10(local_68);
  local_8 = CONCAT31(local_8._1_3_,6);
  FUN_1000e2c0((int *)local_cc);
  iVar4 = FUN_1001c0e0(&DAT_1006b6d8);
  uVar3 = local_18;
  ppppuVar8 = (uint ****)local_2c[0];
  if (iVar4 == 0) {
    puVar10 = (ushort *)&DAT_1006b6c0;
    if (7 < DAT_1006b6d4) {
      puVar10 = DAT_1006b6c0;
    }
    ppppuVar7 = local_2c;
    if (7 < local_18) {
      ppppuVar7 = (uint ****)local_2c[0];
    }
    if (local_1c != DAT_1006b6d0) goto LAB_1001e2bf;
    iVar4 = FUN_10009c60((ushort *)ppppuVar7,puVar10,local_1c);
    if (iVar4 != 0) goto LAB_1001e2bf;
  }
  else {
LAB_1001e2bf:
    local_30 = &stack0xfffffeac;
    local_34 = &stack0xfffffeac;
    FUN_1000eb70(&stack0xfffffeac,&DAT_1006b690);
    local_8._0_1_ = 7;
    ppppuVar7 = local_2c;
    if (7 < uVar3) {
      ppppuVar7 = ppppuVar8;
    }
    pvVar11 = (void *)0x0;
    uVar12 = 0;
    uVar13 = 7;
    ppppuVar8 = ppppuVar7;
    do {
      sVar1 = *(short *)ppppuVar8;
      ppppuVar8 = (uint ****)((int)ppppuVar8 + 2);
    } while (sVar1 != 0);
    FUN_10001d40(&stack0xfffffe94,(uint *)ppppuVar7,(int)ppppuVar8 - ((int)ppppuVar7 + 2) >> 1);
    local_8 = CONCAT31(local_8._1_3_,6);
    FUN_1001dd70(&stack0xfffffec4,pvVar11,in_stack_fffffe98,in_stack_fffffe9c,in_stack_fffffea0,
                 uVar12,uVar13,in_stack_fffffeac,in_stack_fffffeb0,in_stack_fffffeb4,
                 in_stack_fffffeb8,in_stack_fffffebc,in_stack_fffffec0);
    FUN_1001e750(in_stack_fffffec4);
    ppppuVar8 = (uint ****)local_2c[0];
    uVar3 = local_18;
  }
  if (7 < uVar3) {
    ppppuVar7 = ppppuVar8;
    if (0xfff < uVar3 * 2 + 2) {
      ppppuVar7 = (uint ****)ppppuVar8[-1];
      if (0x1f < (uint)((int)ppppuVar8 + (-4 - (int)ppppuVar7))) {
LAB_1001e39b:
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
    }
    FUN_1002e346(ppppuVar7);
  }
  __Mtx_unlock(0x1006b660);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001e3b0 @ 1001e3b0