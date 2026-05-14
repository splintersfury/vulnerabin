uint * __thiscall
FUN_1001dd70(void *this,void *param_1,uint param_2,uint param_3,uint param_4,undefined4 param_5,
            undefined4 param_6,void *param_7,uint param_8,uint param_9,uint param_10,
            undefined4 param_11,undefined4 param_12)

{
  code *pcVar1;
  int *piVar2;
  uint *puVar3;
  void *pvVar4;
  void *local_88 [5];
  uint local_74;
  void *local_70 [4];
  undefined4 local_60;
  uint local_5c;
  void *local_58;
  void *local_54 [4];
  undefined4 local_44;
  uint local_40;
  void *local_3c [4];
  undefined4 local_2c;
  uint local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined1 local_14;
  undefined3 uStack_13;
  
  puStack_20 = &stack0xfffffffc;
  puStack_18 = &LAB_1004fa54;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(void **)this = param_1;
  *(uint *)((int)this + 4) = param_2;
  *(uint *)((int)this + 8) = param_3;
  *(uint *)((int)this + 0xc) = param_4;
  *(ulonglong *)((int)this + 0x10) = CONCAT44(param_6,param_5);
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(void **)((int)this + 0x18) = param_7;
  *(uint *)((int)this + 0x1c) = param_8;
  *(uint *)((int)this + 0x20) = param_9;
  *(uint *)((int)this + 0x24) = param_10;
  *(ulonglong *)((int)this + 0x28) = CONCAT44(param_12,param_11);
  *(undefined4 *)((int)this + 0x30) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x44) = 7;
  *(undefined2 *)((int)this + 0x30) = 0;
  *(undefined4 *)((int)this + 0x48) = 0;
  *(undefined4 *)((int)this + 0x58) = 0;
  *(undefined4 *)((int)this + 0x5c) = 7;
  *(undefined2 *)((int)this + 0x48) = 0;
  local_24 = (uint)this & 0xffffff00;
  local_14 = 5;
  uStack_13 = 0;
  local_58 = this;
  FUN_10018950(local_54,(uint *)this);
  local_14 = 6;
  piVar2 = (int *)FUN_1000b910(local_3c,(uint *)((int)this + 0x18),(uint *)local_54);
  FUN_10005380((void *)((int)this + 0x30),piVar2);
  if (local_28 < 8) {
LAB_1001deb0:
    local_14 = 5;
    local_2c = 0;
    local_28 = 7;
    local_3c[0] = (void *)((uint)local_3c[0] & 0xffff0000);
    if (7 < local_40) {
      pvVar4 = local_54[0];
      if ((0xfff < local_40 * 2 + 2) &&
         (pvVar4 = *(void **)((int)local_54[0] + -4),
         0x1f < (uint)((int)local_54[0] + (-4 - (int)pvVar4)))) goto LAB_1001e11c;
      FUN_1002e346(pvVar4);
    }
    local_24 = local_24 & 0xffffff00;
    FUN_10023e40(local_88);
    local_24 = local_24 & 0xffffff00;
    local_14 = 7;
    FUN_10018950(local_3c,(uint *)this);
    local_14 = 8;
    puVar3 = (uint *)FUN_1000b910(local_54,(uint *)((int)this + 0x18),(uint *)local_3c);
    local_14 = 9;
    piVar2 = (int *)FUN_1000b910(local_70,puVar3,(uint *)local_88);
    FUN_10005380((void *)((int)this + 0x48),piVar2);
    if (7 < local_5c) {
      pvVar4 = local_70[0];
      if ((0xfff < local_5c * 2 + 2) &&
         (pvVar4 = *(void **)((int)local_70[0] + -4),
         0x1f < (uint)((int)local_70[0] + (-4 - (int)pvVar4)))) goto LAB_1001e121;
      FUN_1002e346(pvVar4);
    }
    local_60 = 0;
    local_5c = 7;
    local_70[0] = (void *)((uint)local_70[0] & 0xffff0000);
    if (7 < local_40) {
      pvVar4 = local_54[0];
      if ((0xfff < local_40 * 2 + 2) &&
         (pvVar4 = *(void **)((int)local_54[0] + -4),
         0x1f < (uint)((int)local_54[0] + (-4 - (int)pvVar4)))) goto LAB_1001e121;
      FUN_1002e346(pvVar4);
    }
    local_44 = 0;
    local_40 = 7;
    local_54[0] = (void *)((uint)local_54[0] & 0xffff0000);
    if (7 < local_28) {
      pvVar4 = local_3c[0];
      if ((0xfff < local_28 * 2 + 2) &&
         (pvVar4 = *(void **)((int)local_3c[0] + -4),
         0x1f < (uint)((int)local_3c[0] + (-4 - (int)pvVar4)))) goto LAB_1001e121;
      FUN_1002e346(pvVar4);
    }
    local_2c = 0;
    local_28 = 7;
    local_3c[0] = (void *)((uint)local_3c[0] & 0xffff0000);
    if (7 < local_74) {
      pvVar4 = local_88[0];
      if ((0xfff < local_74 * 2 + 2) &&
         (pvVar4 = *(void **)((int)local_88[0] + -4),
         0x1f < (uint)((int)local_88[0] + (-4 - (int)pvVar4)))) goto LAB_1001e121;
      FUN_1002e346(pvVar4);
    }
    ExceptionList = local_1c;
    return (uint *)this;
  }
  pvVar4 = local_3c[0];
  if ((local_28 * 2 + 2 < 0x1000) ||
     (pvVar4 = *(void **)((int)local_3c[0] + -4),
     (uint)((int)local_3c[0] + (-4 - (int)pvVar4)) < 0x20)) {
    FUN_1002e346(pvVar4);
    goto LAB_1001deb0;
  }
LAB_1001e11c:
  FUN_10032f7f();
LAB_1001e121:
  FUN_10032f7f();
  FUN_10032f7f();
  pcVar1 = (code *)swi(3);
  puVar3 = (uint *)(*pcVar1)();
  return puVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001e130 @ 1001e130