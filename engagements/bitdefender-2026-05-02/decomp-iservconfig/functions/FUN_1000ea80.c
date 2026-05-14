void __fastcall FUN_1000ea80(uint *param_1)

{
  void *pvVar1;
  code *pcVar2;
  uint *puVar3;
  void *pvVar4;
  uint *puVar5;
  uint uVar6;
  
  if (7 < param_1[5]) {
    uVar6 = param_1[4];
    if (uVar6 < 8) {
      puVar3 = (uint *)*param_1;
      FUN_100301d0(param_1,puVar3,uVar6 * 2 + 2);
      puVar5 = puVar3;
      if ((param_1[5] * 2 + 2 < 0x1000) ||
         (puVar5 = (uint *)puVar3[-1], (uint)((int)puVar3 + (-4 - (int)puVar5)) < 0x20)) {
        FUN_1002e346(puVar5);
        param_1[5] = 7;
        return;
      }
LAB_1000eb62:
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    uVar6 = uVar6 | 7;
    if (0x7ffffffe < uVar6) {
      uVar6 = 0x7ffffffe;
    }
    if (uVar6 < param_1[5]) {
      puVar3 = (uint *)FUN_10001e50(-(uint)(0xfffffffe < uVar6) | uVar6 + 1);
      FUN_100301d0(puVar3,(uint *)*param_1,param_1[4] * 2 + 2);
      pvVar1 = (void *)*param_1;
      pvVar4 = pvVar1;
      if ((0xfff < param_1[5] * 2 + 2) &&
         (pvVar4 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar4))))
      goto LAB_1000eb62;
      FUN_1002e346(pvVar4);
      *param_1 = (uint)puVar3;
      param_1[5] = uVar6;
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000eb70 @ 1000eb70