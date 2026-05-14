void * FUN_1001ab40(uint param_1)

{
  code *pcVar1;
  uint uVar2;
  void *pvVar3;
  void *pvVar4;
  
  if (param_1 < 0x10000000) {
    uVar2 = param_1 * 0x10;
    if (uVar2 < 0x1000) {
      if (uVar2 != 0) {
        pvVar3 = operator_new(uVar2);
        return pvVar3;
      }
      return (void *)0x0;
    }
    if (uVar2 < uVar2 + 0x23) {
      pvVar3 = operator_new(uVar2 + 0x23);
      if (pvVar3 != (void *)0x0) {
        pvVar4 = (void *)((int)pvVar3 + 0x23U & 0xffffffe0);
        *(void **)((int)pvVar4 + -4) = pvVar3;
        return pvVar4;
      }
      goto LAB_1001ab96;
    }
  }
  FUN_10001fb0();
LAB_1001ab96:
  FUN_10032f7f();
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001aba0 @ 1001aba0