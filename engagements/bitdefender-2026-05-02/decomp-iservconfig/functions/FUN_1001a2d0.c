void __thiscall FUN_1001a2d0(void *this,undefined1 *param_1,undefined1 *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  undefined4 uVar5;
  void *this_00;
  int iVar6;
  code *pcVar7;
  char cVar8;
  undefined4 uVar9;
  char cVar10;
  char local_40 [8];
  undefined4 local_38;
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
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  uVar3 = *(uint *)((int)this + 0x1c);
  if (((int)uVar3 < 0) && (uVar3 != 0)) {
    iVar6 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    iVar6 = (uVar3 >> 5) * 4;
  }
  uVar1 = (uVar3 & 0x1f) - 1;
  if ((uVar3 & 0x1f) == 0) {
    iVar2 = -((~uVar1 >> 5) * 4 + 4);
  }
  else {
    iVar2 = (uVar1 >> 5) * 4;
  }
  local_34 = uVar1 & 0x1f;
  if ((*(uint *)(*(int *)((int)this + 0x10) + iVar6 + iVar2) & 1 << (sbyte)local_34) == 0) {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    goto LAB_1001a54e;
  }
  local_30[0] = '\x04';
  local_38 = CONCAT31(local_38._1_3_,*param_2);
  local_28 = CONCAT44(uVar1,local_38) & 0x1fffffffff;
  local_8 = 0;
  local_34 = *(int *)((int)this + 8) - *(int *)((int)this + 4) >> 2;
  local_1c[0] = 5;
  if (*(int **)((int)this + 0x5c) == (int *)0x0) {
    FUN_1002c837();
    pcVar7 = (code *)swi(3);
    (*pcVar7)();
    return;
  }
  cVar10 = (**(code **)(**(int **)((int)this + 0x5c) + 8))(&local_34,local_1c,local_30,local_18);
  cVar8 = local_30[0];
  if (cVar10 == '\0') {
LAB_1001a53c:
    *(undefined4 *)(param_1 + 4) = 0;
    *param_1 = 0;
  }
  else {
    uVar5 = (undefined4)local_28;
    uVar9 = local_28._4_4_;
    if (*(int *)((int)this + 4) == *(int *)((int)this + 8)) {
                    /* WARNING: Load size is inaccurate */
      pcVar4 = *this;
      local_30[0] = '\0';
      local_28 = 0;
      local_40[0] = *pcVar4;
      *pcVar4 = cVar8;
      local_34 = *(uint *)(pcVar4 + 0xc);
      local_38 = *(undefined4 *)(pcVar4 + 8);
      *(undefined4 *)(pcVar4 + 8) = uVar5;
      *(undefined4 *)(pcVar4 + 0xc) = uVar9;
      FUN_1000e760(local_40);
                    /* WARNING: Load size is inaccurate */
      uVar5 = *this;
      *param_1 = 1;
      *(undefined4 *)(param_1 + 4) = uVar5;
    }
    else {
      pcVar4 = *(char **)(*(int *)((int)this + 8) + -4);
      if (pcVar4 == (char *)0x0) goto LAB_1001a53c;
      if (*pcVar4 == '\x02') {
        this_00 = *(void **)(pcVar4 + 8);
        pcVar4 = *(char **)((int)this_00 + 4);
        if (pcVar4 == *(char **)((int)this_00 + 8)) {
          FUN_1001b6c0(this_00,pcVar4,local_30);
        }
        else {
          *pcVar4 = local_30[0];
          *(undefined4 *)(pcVar4 + 8) = (undefined4)local_28;
          *(undefined4 *)(pcVar4 + 0xc) = local_28._4_4_;
          local_30[0] = '\0';
          local_28 = 0;
          *(int *)((int)this_00 + 4) = *(int *)((int)this_00 + 4) + 0x10;
        }
        iVar6 = *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + -4) + 8) + 4);
        *param_1 = 1;
        *(int *)(param_1 + 4) = iVar6 + -0x10;
      }
      else {
        uVar3 = *(uint *)((int)this + 0x2c);
        if (((int)uVar3 < 0) && (uVar3 != 0)) {
          iVar6 = -((~uVar3 >> 5) * 4 + 4);
        }
        else {
          iVar6 = (uVar3 >> 5) * 4;
        }
        uVar1 = (uVar3 & 0x1f) - 1;
        if ((uVar3 & 0x1f) == 0) {
          iVar2 = -((~uVar1 >> 5) * 4 + 4);
        }
        else {
          iVar2 = (uVar1 >> 5) * 4;
        }
        uVar3 = *(uint *)(*(int *)((int)this + 0x20) + iVar6 + iVar2);
        FUN_10017fb0((int *)((int)this + 0x20));
        cVar8 = local_30[0];
        if ((uVar3 & 1 << ((byte)uVar1 & 0x1f)) == 0) goto LAB_1001a53c;
        uVar5 = (undefined4)local_28;
        uVar9 = local_28._4_4_;
        pcVar4 = *(char **)((int)this + 0x30);
        local_30[0] = '\0';
        local_28 = 0;
        local_40[0] = *pcVar4;
        *pcVar4 = cVar8;
        local_34 = *(uint *)(pcVar4 + 0xc);
        local_38 = *(undefined4 *)(pcVar4 + 8);
        *(undefined4 *)(pcVar4 + 8) = uVar5;
        *(undefined4 *)(pcVar4 + 0xc) = uVar9;
        FUN_1000e760(local_40);
        *param_1 = 1;
        *(undefined4 *)(param_1 + 4) = *(undefined4 *)((int)this + 0x30);
      }
    }
  }
  FUN_1000e760(local_30);
LAB_1001a54e:
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001a580 @ 1001a580