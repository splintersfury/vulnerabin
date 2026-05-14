undefined4 * __thiscall FUN_10008b90(void *this,uint param_1,undefined2 param_2)

{
  uint *puVar1;
  code *pcVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  uint uVar6;
  
  puVar1 = (uint *)((int)this + 0x10);
  *(undefined4 *)this = 0;
  *puVar1 = 0;
  *(uint *)((int)this + 0x14) = 7;
  if (param_1 < 8) {
    *puVar1 = param_1;
    if (param_1 != 0) {
      puVar5 = (undefined4 *)this;
      for (uVar6 = param_1 >> 1; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar5 = CONCAT22(param_2,param_2);
        puVar5 = puVar5 + 1;
      }
      for (uVar6 = (uint)((param_1 & 1) != 0); uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined2 *)puVar5 = param_2;
        puVar5 = (undefined4 *)((int)puVar5 + 2);
      }
    }
    *(undefined2 *)((int)this + param_1 * 2) = 0;
    return (undefined4 *)this;
  }
  if (param_1 < 0x7fffffff) {
    uVar6 = param_1 | 7;
    if (uVar6 < 0x7fffffff) {
      if (uVar6 < 10) {
        uVar6 = 10;
      }
      uVar3 = uVar6 + 1;
    }
    else {
      uVar6 = 0x7ffffffe;
      uVar3 = 0x7fffffff;
    }
    puVar4 = (undefined4 *)FUN_10001e50(uVar3);
    *puVar1 = param_1;
    *(uint *)((int)this + 0x14) = uVar6;
    puVar5 = puVar4;
    for (uVar6 = param_1 >> 1; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar5 = CONCAT22(param_2,param_2);
      puVar5 = puVar5 + 1;
    }
    for (uVar6 = (uint)((param_1 & 1) != 0); uVar6 != 0; uVar6 = uVar6 - 1) {
      *(undefined2 *)puVar5 = param_2;
      puVar5 = (undefined4 *)((int)puVar5 + 2);
    }
    *(undefined2 *)((int)puVar4 + param_1 * 2) = 0;
    *(undefined4 **)this = puVar4;
    return (undefined4 *)this;
  }
  FUN_10001eb0();
  pcVar2 = (code *)swi(3);
  puVar5 = (undefined4 *)(*pcVar2)();
  return puVar5;
}


// FUNCTION_END

// FUNCTION_START: FUN_10008c80 @ 10008c80