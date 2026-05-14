void __thiscall FUN_10019d90(void *this,undefined1 *param_1,undefined4 *param_2)

{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  undefined4 uVar4;
  void *this_00;
  int iVar5;
  code *pcVar6;
  char cVar7;
  undefined4 uVar8;
  char cVar9;
  uint uVar10;
  char local_48 [8];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 *local_38;
  uint local_34;
  char local_30 [8];
  undefined8 local_28;
  undefined1 local_1c [4];
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f61d;
  local_10 = ExceptionList;
  uVar10 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  uVar2 = *(uint *)((int)this + 0x1c);
  if (((int)uVar2 < 0) && (uVar2 != 0)) {
    iVar5 = -((~uVar2 >> 5) * 4 + 4);
  }
  else {
    iVar5 = (uVar2 >> 5) * 4;
  }
  local_34 = (uVar2 & 0x1f) - 1;
  if ((uVar2 & 0x1f) == 0) {
    iVar1 = -((~local_34 >> 5) * 4 + 4);
  }
  else {
    iVar1 = (local_34 >> 5) * 4;
  }
  local_34 = local_34 & 0x1f;
  local_38 = (undefined4 *)this;
  local_18 = uVar10;
  if ((*(uint *)(*(int *)((int)this + 0x10) + iVar5 + iVar1) & 1 << (sbyte)local_34) == 0) {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    goto LAB_1001a006;
  }
  local_30[0] = '\0';
  local_28 = 0;
  FUN_1001bd80(local_30,param_2);
  local_8 = 0;
  local_34 = *(int *)((int)this + 8) - *(int *)((int)this + 4) >> 2;
  local_1c[0] = 5;
  if (*(int **)((int)this + 0x5c) == (int *)0x0) {
    FUN_1002c837();
    pcVar6 = (code *)swi(3);
    (*pcVar6)();
    return;
  }
  cVar9 = (**(code **)(**(int **)((int)this + 0x5c) + 8))(&local_34,local_1c,local_30,uVar10);
  cVar7 = local_30[0];
  if (cVar9 == '\0') {
LAB_10019ff4:
    *(undefined4 *)(param_1 + 4) = 0;
    *param_1 = 0;
  }
  else {
    uVar4 = (undefined4)local_28;
    uVar8 = local_28._4_4_;
    if (*(int *)((int)this + 4) == *(int *)((int)this + 8)) {
      pcVar3 = (char *)*local_38;
      local_30[0] = '\0';
      local_28 = 0;
      local_48[0] = *pcVar3;
      *pcVar3 = cVar7;
      local_3c = *(undefined4 *)(pcVar3 + 0xc);
      local_40 = *(undefined4 *)(pcVar3 + 8);
      *(undefined4 *)(pcVar3 + 8) = uVar4;
      *(undefined4 *)(pcVar3 + 0xc) = uVar8;
      FUN_1000e760(local_48);
      uVar4 = *local_38;
      *param_1 = 1;
      *(undefined4 *)(param_1 + 4) = uVar4;
    }
    else {
      pcVar3 = *(char **)(*(int *)((int)this + 8) + -4);
      if (pcVar3 == (char *)0x0) goto LAB_10019ff4;
      if (*pcVar3 == '\x02') {
        this_00 = *(void **)(pcVar3 + 8);
        pcVar3 = *(char **)((int)this_00 + 4);
        if (pcVar3 == *(char **)((int)this_00 + 8)) {
          FUN_1001b6c0(this_00,pcVar3,local_30);
        }
        else {
          *pcVar3 = local_30[0];
          *(undefined4 *)(pcVar3 + 8) = (undefined4)local_28;
          *(undefined4 *)(pcVar3 + 0xc) = local_28._4_4_;
          local_30[0] = '\0';
          local_28 = 0;
          *(int *)((int)this_00 + 4) = *(int *)((int)this_00 + 4) + 0x10;
        }
        iVar5 = *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + -4) + 8) + 4);
        *param_1 = 1;
        *(int *)(param_1 + 4) = iVar5 + -0x10;
      }
      else {
        uVar2 = *(uint *)((int)this + 0x2c);
        if (((int)uVar2 < 0) && (uVar2 != 0)) {
          iVar5 = -((~uVar2 >> 5) * 4 + 4);
        }
        else {
          iVar5 = (uVar2 >> 5) * 4;
        }
        uVar10 = (uVar2 & 0x1f) - 1;
        if ((uVar2 & 0x1f) == 0) {
          iVar1 = -((~uVar10 >> 5) * 4 + 4);
        }
        else {
          iVar1 = (uVar10 >> 5) * 4;
        }
        uVar2 = *(uint *)(*(int *)((int)this + 0x20) + iVar5 + iVar1);
        FUN_10017fb0((int *)((int)this + 0x20));
        cVar7 = local_30[0];
        if ((uVar2 & 1 << ((byte)uVar10 & 0x1f)) == 0) goto LAB_10019ff4;
        uVar4 = (undefined4)local_28;
        uVar8 = local_28._4_4_;
        pcVar3 = (char *)local_38[0xc];
        local_30[0] = '\0';
        local_28 = 0;
        local_48[0] = *pcVar3;
        *pcVar3 = cVar7;
        local_3c = *(undefined4 *)(pcVar3 + 0xc);
        local_40 = *(undefined4 *)(pcVar3 + 8);
        *(undefined4 *)(pcVar3 + 8) = uVar4;
        *(undefined4 *)(pcVar3 + 0xc) = uVar8;
        FUN_1000e760(local_48);
        *param_1 = 1;
        *(undefined4 *)(param_1 + 4) = local_38[0xc];
      }
    }
  }
  FUN_1000e760(local_30);
LAB_1001a006:
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001a030 @ 1001a030