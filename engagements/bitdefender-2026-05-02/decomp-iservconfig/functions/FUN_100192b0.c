void __thiscall FUN_100192b0(void *this,undefined1 *param_1,char *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  void *this_00;
  char cVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  char local_40 [8];
  undefined4 local_38;
  undefined4 local_34;
  char local_30;
  undefined3 uStack_2f;
  int *local_2c;
  char local_28 [8];
  undefined8 local_20;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f53d;
  local_10 = ExceptionList;
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  uVar3 = *(uint *)((int)this + 0x1c);
  if (((int)uVar3 < 0) && (uVar3 != 0)) {
    iVar8 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    iVar8 = (uVar3 >> 5) * 4;
  }
  uVar1 = (uVar3 & 0x1f) - 1;
  if ((uVar3 & 0x1f) == 0) {
    iVar2 = -((~uVar1 >> 5) * 4 + 4);
  }
  else {
    iVar2 = (uVar1 >> 5) * 4;
  }
  local_2c = (int *)this;
  if ((*(uint *)(*(int *)((int)this + 0x10) + iVar8 + iVar2) & 1 << ((byte)uVar1 & 0x1f)) == 0) {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    goto LAB_100194e5;
  }
  local_28[0] = *param_2;
  _local_30 = CONCAT31(uStack_2f,local_28[0]);
  FUN_1000f600(&local_20,local_28[0]);
  cVar5 = local_28[0];
  local_8 = 0;
  uVar6 = (undefined4)local_20;
  uVar7 = local_20._4_4_;
  if (*(int *)((int)this + 4) == *(int *)((int)this + 8)) {
    pcVar4 = (char *)*local_2c;
    local_28[0] = '\0';
    local_20 = 0;
    local_40[0] = *pcVar4;
    *pcVar4 = cVar5;
    local_34 = *(undefined4 *)(pcVar4 + 0xc);
    local_38 = *(undefined4 *)(pcVar4 + 8);
    *(undefined4 *)(pcVar4 + 8) = uVar6;
    *(undefined4 *)(pcVar4 + 0xc) = uVar7;
    FUN_1000e760(local_40);
    iVar8 = *local_2c;
    *param_1 = 1;
LAB_100194da:
    *(int *)(param_1 + 4) = iVar8;
  }
  else {
    pcVar4 = *(char **)(*(int *)((int)this + 8) + -4);
    if (pcVar4 != (char *)0x0) {
      if (*pcVar4 == '\x02') {
        this_00 = *(void **)(pcVar4 + 8);
        pcVar4 = *(char **)((int)this_00 + 4);
        if (pcVar4 == *(char **)((int)this_00 + 8)) {
          FUN_1001b6c0(this_00,pcVar4,local_28);
        }
        else {
          *pcVar4 = local_28[0];
          *(undefined4 *)(pcVar4 + 8) = (undefined4)local_20;
          *(undefined4 *)(pcVar4 + 0xc) = local_20._4_4_;
          local_28[0] = '\0';
          local_20 = 0;
          *(int *)((int)this_00 + 4) = *(int *)((int)this_00 + 4) + 0x10;
        }
        iVar8 = *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + -4) + 8) + 4) + -0x10;
        *param_1 = 1;
      }
      else {
        uVar3 = *(uint *)((int)this + 0x2c);
        if (((int)uVar3 < 0) && (uVar3 != 0)) {
          iVar8 = -((~uVar3 >> 5) * 4 + 4);
        }
        else {
          iVar8 = (uVar3 >> 5) * 4;
        }
        uVar1 = (uVar3 & 0x1f) - 1;
        if ((uVar3 & 0x1f) == 0) {
          iVar2 = -((~uVar1 >> 5) * 4 + 4);
        }
        else {
          iVar2 = (uVar1 >> 5) * 4;
        }
        uVar3 = *(uint *)(*(int *)((int)this + 0x20) + iVar8 + iVar2);
        FUN_10017fb0((int *)((int)this + 0x20));
        cVar5 = local_28[0];
        if ((uVar3 & 1 << ((byte)uVar1 & 0x1f)) == 0) goto LAB_100193c4;
        uVar6 = (undefined4)local_20;
        uVar7 = local_20._4_4_;
        pcVar4 = (char *)local_2c[0xc];
        local_28[0] = '\0';
        local_20 = 0;
        local_40[0] = *pcVar4;
        *pcVar4 = cVar5;
        local_34 = *(undefined4 *)(pcVar4 + 0xc);
        local_38 = *(undefined4 *)(pcVar4 + 8);
        *(undefined4 *)(pcVar4 + 8) = uVar6;
        *(undefined4 *)(pcVar4 + 0xc) = uVar7;
        FUN_1000e760(local_40);
        *param_1 = 1;
        iVar8 = local_2c[0xc];
      }
      goto LAB_100194da;
    }
LAB_100193c4:
    *param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_1000e760(local_28);
LAB_100194e5:
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10019510 @ 10019510

/* WARNING: Instruction at (ram,0x10019794) overlaps instruction at (ram,0x10019792)
    */