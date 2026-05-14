void __thiscall FUN_10017b00(void *this,uint *param_1)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  void *pvVar6;
  int *piVar7;
  char local_48 [8];
  int local_40;
  int local_3c;
  char local_38 [8];
  undefined8 local_30;
  undefined8 local_28;
  undefined1 local_1d;
  char local_1c [4];
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f26d;
  local_10 = ExceptionList;
  uVar5 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_30 = 0;
  local_38[0] = '\x03';
  local_28 = 0;
  local_18 = uVar5;
  pvVar6 = operator_new(0x18);
  local_28._0_4_ = &local_1d;
  local_8 = 0;
  local_28._4_4_ = pvVar6;
  FUN_100056d0(pvVar6,param_1);
  local_30 = CONCAT44(local_28._4_4_,pvVar6);
  local_8 = 1;
  local_1c[0] = '\x04';
  local_28 = CONCAT44(*(int *)((int)this + 8) - *(int *)((int)this + 4) >> 2,(undefined1 *)local_28)
  ;
  if (*(int **)((int)this + 0x5c) != (int *)0x0) {
    local_1c[0] = (**(code **)(**(int **)((int)this + 0x5c) + 8))
                            ((int)&local_28 + 4,local_1c,local_38,uVar5);
    FUN_100125f0((void *)((int)this + 0x20),local_1c);
    if ((local_1c[0] != '\0') && (iVar1 = *(int *)(*(int *)((int)this + 8) + -4), iVar1 != 0)) {
      pvVar6 = *(void **)(iVar1 + 8);
      FUN_10011220(local_48,(undefined1 *)((int)this + 0x68));
      local_8 = CONCAT31(local_8._1_3_,2);
      piVar7 = FUN_100183d0(pvVar6,param_1);
      iVar4 = *piVar7;
      *(char *)piVar7 = local_48[0];
      iVar1 = piVar7[3];
      iVar2 = piVar7[2];
      piVar7[3] = local_3c;
      piVar7[2] = local_40;
      local_48[0] = (char)iVar4;
      local_40 = iVar2;
      local_3c = iVar1;
      FUN_1000e760(local_48);
      *(int **)((int)this + 0x30) = piVar7;
    }
    FUN_1000e760(local_38);
    ExceptionList = local_10;
    FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_1002c837();
  pcVar3 = (code *)swi(3);
  (*pcVar3)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10017c40 @ 10017c40