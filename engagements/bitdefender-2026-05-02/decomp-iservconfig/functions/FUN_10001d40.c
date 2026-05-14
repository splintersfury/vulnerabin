uint * __thiscall FUN_10001d40(void *this,uint *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  void *pvVar3;
  code *pcVar4;
  uint *puVar5;
  void *pvVar6;
  uint uVar7;
  uint *local_8;
  
  uVar2 = *(uint *)((int)this + 0x14);
  if (param_2 <= uVar2) {
    local_8 = (uint *)this;
    if (7 < uVar2) {
                    /* WARNING: Load size is inaccurate */
      local_8 = *this;
    }
    *(uint *)((int)this + 0x10) = param_2;
    FUN_100301d0(local_8,param_1,param_2 * 2);
    *(undefined2 *)(param_2 * 2 + (int)local_8) = 0;
    return (uint *)this;
  }
  if (0x7ffffffe < param_2) {
LAB_10001e44:
    FUN_10001eb0();
    pcVar4 = (code *)swi(3);
    puVar5 = (uint *)(*pcVar4)();
    return puVar5;
  }
  uVar7 = param_2 | 7;
  if (uVar7 < 0x7fffffff) {
    if (0x7ffffffe - (uVar2 >> 1) < uVar2) {
      uVar7 = 0x7ffffffe;
    }
    else {
      uVar1 = (uVar2 >> 1) + uVar2;
      if (uVar7 < uVar1) {
        uVar7 = uVar1;
      }
    }
  }
  else {
    uVar7 = 0x7ffffffe;
  }
  puVar5 = (uint *)FUN_10001e50(uVar7 + 1);
  *(uint *)((int)this + 0x14) = uVar7;
  *(uint *)((int)this + 0x10) = param_2;
  FUN_100301d0(puVar5,param_1,param_2 * 2);
  *(undefined2 *)(param_2 * 2 + (int)puVar5) = 0;
  if (7 < uVar2) {
                    /* WARNING: Load size is inaccurate */
    pvVar3 = *this;
    pvVar6 = pvVar3;
    if ((0xfff < uVar2 * 2 + 2) &&
       (pvVar6 = *(void **)((int)pvVar3 + -4), 0x1f < (uint)((int)pvVar3 + (-4 - (int)pvVar6)))) {
      FUN_10032f7f();
      goto LAB_10001e44;
    }
    FUN_1002e346(pvVar6);
  }
  *(uint **)this = puVar5;
  return (uint *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001e50 @ 10001e50