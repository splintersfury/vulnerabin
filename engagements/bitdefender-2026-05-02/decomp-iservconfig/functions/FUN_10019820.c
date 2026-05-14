void __thiscall FUN_10019820(void *this,undefined1 *param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  undefined4 uVar5;
  int iVar6;
  code *pcVar7;
  char cVar8;
  undefined4 uVar9;
  char cVar10;
  uint uVar11;
  void *pvVar12;
  char local_48 [8];
  undefined4 local_40;
  uint *local_3c [3];
  char local_30 [8];
  undefined8 local_28;
  undefined1 local_1c [4];
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f5e5;
  local_10 = ExceptionList;
  uVar11 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  uVar3 = *(uint *)((int)this + 0x1c);
  local_3c[0] = param_2;
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
  local_18 = uVar11;
  if ((*(uint *)(*(int *)((int)this + 0x10) + iVar6 + iVar2) & 1 << ((byte)uVar1 & 0x1f)) == 0) {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    goto LAB_10019ac4;
  }
  local_30[0] = '\x03';
  local_28 = 0;
  pvVar12 = operator_new(0x18);
  local_8 = 0;
  FUN_100056d0(pvVar12,local_3c[0]);
  local_28 = CONCAT44(local_3c[0],pvVar12);
  local_8 = 1;
  local_3c[0] = (uint *)(*(int *)((int)this + 8) - *(int *)((int)this + 4) >> 2);
  local_1c[0] = 5;
  if (*(int **)((int)this + 0x5c) == (int *)0x0) {
    FUN_1002c837();
    pcVar7 = (code *)swi(3);
    (*pcVar7)();
    return;
  }
  cVar10 = (**(code **)(**(int **)((int)this + 0x5c) + 8))(local_3c,local_1c,local_30,uVar11);
  cVar8 = local_30[0];
  if (cVar10 == '\0') {
LAB_10019ab2:
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
      local_48[0] = *pcVar4;
      *pcVar4 = cVar8;
      local_3c[0] = *(uint **)(pcVar4 + 0xc);
      local_40 = *(undefined4 *)(pcVar4 + 8);
      *(undefined4 *)(pcVar4 + 8) = uVar5;
      *(undefined4 *)(pcVar4 + 0xc) = uVar9;
      FUN_1000e760(local_48);
                    /* WARNING: Load size is inaccurate */
      uVar5 = *this;
      *param_1 = 1;
      *(undefined4 *)(param_1 + 4) = uVar5;
    }
    else {
      pcVar4 = *(char **)(*(int *)((int)this + 8) + -4);
      if (pcVar4 == (char *)0x0) goto LAB_10019ab2;
      if (*pcVar4 == '\x02') {
        pvVar12 = *(void **)(pcVar4 + 8);
        pcVar4 = *(char **)((int)pvVar12 + 4);
        if (pcVar4 == *(char **)((int)pvVar12 + 8)) {
          FUN_1001b6c0(pvVar12,pcVar4,local_30);
        }
        else {
          *pcVar4 = local_30[0];
          *(undefined4 *)(pcVar4 + 8) = (undefined4)local_28;
          *(undefined4 *)(pcVar4 + 0xc) = local_28._4_4_;
          local_30[0] = '\0';
          local_28 = 0;
          *(int *)((int)pvVar12 + 4) = *(int *)((int)pvVar12 + 4) + 0x10;
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
        uVar11 = (uVar3 & 0x1f) - 1;
        if ((uVar3 & 0x1f) == 0) {
          iVar2 = -((~uVar11 >> 5) * 4 + 4);
        }
        else {
          iVar2 = (uVar11 >> 5) * 4;
        }
        uVar3 = *(uint *)(*(int *)((int)this + 0x20) + iVar6 + iVar2);
        FUN_10017fb0((int *)((int)this + 0x20));
        cVar8 = local_30[0];
        if ((uVar3 & 1 << ((byte)uVar11 & 0x1f)) == 0) goto LAB_10019ab2;
        uVar5 = (undefined4)local_28;
        uVar9 = local_28._4_4_;
        pcVar4 = *(char **)((int)this + 0x30);
        local_30[0] = '\0';
        local_28 = 0;
        local_48[0] = *pcVar4;
        *pcVar4 = cVar8;
        local_3c[0] = *(uint **)(pcVar4 + 0xc);
        local_40 = *(undefined4 *)(pcVar4 + 8);
        *(undefined4 *)(pcVar4 + 8) = uVar5;
        *(undefined4 *)(pcVar4 + 0xc) = uVar9;
        FUN_1000e760(local_48);
        *param_1 = 1;
        *(undefined4 *)(param_1 + 4) = *(undefined4 *)((int)this + 0x30);
      }
    }
  }
  FUN_1000e760(local_30);
LAB_10019ac4:
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10019af0 @ 10019af0