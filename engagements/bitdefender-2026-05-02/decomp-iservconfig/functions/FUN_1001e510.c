void FUN_1001e510(void)

{
  void *pvVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  int *piVar5;
  int *piVar6;
  LPCSTR **pppCVar7;
  void *in_stack_fffffea4;
  uint in_stack_fffffea8;
  uint in_stack_fffffeac;
  uint in_stack_fffffeb0;
  undefined4 in_stack_fffffeb4;
  undefined4 in_stack_fffffeb8;
  uint *in_stack_fffffebc;
  uint local_d8 [13];
  int local_a4 [6];
  LPCSTR *local_8c [5];
  uint local_78;
  int local_74 [4];
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 *local_44;
  undefined1 *local_40;
  void *local_3c;
  uint uStack_38;
  uint uStack_34;
  uint uStack_30;
  undefined4 local_2c;
  undefined4 uStack_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  puStack_18 = &LAB_1004fb2e;
  local_1c = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_44 = &DAT_1006b6c0;
  DAT_1006b6c0 = 0;
  DAT_1006b6d0 = 0;
  DAT_1006b6d4 = 7;
  _DAT_1006b6d8 = 0;
  _DAT_1006b6e8 = 0;
  _DAT_1006b6ec = 7;
  _DAT_1006b6f0 = 0;
  _DAT_1006b700 = 0;
  _DAT_1006b704 = 7;
  _DAT_1006b708 = 0;
  _DAT_1006b718 = 0;
  _DAT_1006b71c = 7;
  local_14 = 0;
  DAT_1006b720 = (void *)0x0;
  _DAT_1006b724 = 0;
  local_24 = uVar4;
  DAT_1006b720 = operator_new(0x2c);
  *(void **)DAT_1006b720 = DAT_1006b720;
  *(void **)((int)DAT_1006b720 + 4) = DAT_1006b720;
  *(void **)((int)DAT_1006b720 + 8) = DAT_1006b720;
  *(undefined2 *)((int)DAT_1006b720 + 0xc) = 0x101;
  local_14._0_1_ = 1;
  DAT_1006b728 = (void *)0x0;
  _DAT_1006b72c = 0;
  DAT_1006b728 = operator_new(0x2c);
  *(void **)DAT_1006b728 = DAT_1006b728;
  *(void **)((int)DAT_1006b728 + 4) = DAT_1006b728;
  *(void **)((int)DAT_1006b728 + 8) = DAT_1006b728;
  *(undefined2 *)((int)DAT_1006b728 + 0xc) = 0x101;
  local_14._0_1_ = 2;
  piVar5 = (int *)FUN_1000bdf0(local_d8,&DAT_1006b690);
  local_64 = 0;
  local_60 = 0xf;
  local_74[0] = 0;
  local_4c = 0;
  local_48 = 0xf;
  local_5c = 0;
  piVar6 = local_74;
  if ((char)piVar5[0xc] == '\0') {
    piVar6 = piVar5;
  }
  FUN_10017630(local_a4,piVar6);
  pppCVar7 = local_8c;
  if (0xf < local_78) {
    pppCVar7 = (LPCSTR **)local_8c[0];
  }
  FUN_1001c8a0(&local_3c,(LPCSTR)pppCVar7,uVar4);
  FUN_1000bb10(local_a4);
  FUN_1000bb10(local_74);
  local_14 = CONCAT31(local_14._1_3_,7);
  FUN_1000e2c0((int *)local_d8);
  local_40 = &stack0xfffffea4;
  FUN_1000eb70(&stack0xfffffea4,&DAT_1006b690);
  uVar3 = uStack_28;
  uVar2 = local_2c;
  pvVar1 = local_3c;
  local_2c = 0;
  uStack_28 = 7;
  local_3c = (void *)((uint)local_3c & 0xffff0000);
  FUN_1001dd70(&stack0xfffffebc,pvVar1,uStack_38,uStack_34,uStack_30,uVar2,uVar3,in_stack_fffffea4,
               in_stack_fffffea8,in_stack_fffffeac,in_stack_fffffeb0,in_stack_fffffeb4,
               in_stack_fffffeb8);
  FUN_1001e750(in_stack_fffffebc);
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001e750 @ 1001e750