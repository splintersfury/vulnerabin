void __fastcall FUN_10005490(uint *param_1)

{
  code *pcVar1;
  void *pvVar2;
  void *pvVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  uint *puVar7;
  
  if (param_1[5] < 0x10) {
    return;
  }
  uVar5 = param_1[4];
  if (uVar5 < 0x10) {
    puVar7 = (uint *)*param_1;
    FUN_100301d0(param_1,puVar7,uVar5 + 1);
    puVar6 = puVar7;
    if ((param_1[5] + 1 < 0x1000) ||
       (puVar6 = (uint *)puVar7[-1], (uint)((int)puVar7 + (-4 - (int)puVar6)) < 0x20)) {
      FUN_1002e346(puVar6);
      param_1[5] = 0xf;
      return;
    }
  }
  else {
    uVar5 = uVar5 | 0xf;
    if (0x7fffffff < uVar5) {
      uVar5 = 0x7fffffff;
    }
    if (param_1[5] <= uVar5) {
      return;
    }
    uVar4 = -(uint)(0xfffffffe < uVar5) | uVar5 + 1;
    if (uVar4 < 0x1000) {
      if (uVar4 == 0) {
        puVar7 = (uint *)0x0;
      }
      else {
        puVar7 = (uint *)operator_new(uVar4);
      }
    }
    else {
      if (uVar4 + 0x23 <= uVar4) goto LAB_10005595;
      pvVar2 = operator_new(uVar4 + 0x23);
      if (pvVar2 == (void *)0x0) goto LAB_10005590;
      puVar7 = (uint *)((int)pvVar2 + 0x23U & 0xffffffe0);
      puVar7[-1] = (uint)pvVar2;
    }
    FUN_100301d0(puVar7,(uint *)*param_1,param_1[4] + 1);
    pvVar2 = (void *)*param_1;
    pvVar3 = pvVar2;
    if ((param_1[5] + 1 < 0x1000) ||
       (pvVar3 = *(void **)((int)pvVar2 + -4), (uint)((int)pvVar2 + (-4 - (int)pvVar3)) < 0x20)) {
      FUN_1002e346(pvVar3);
      *param_1 = (uint)puVar7;
      param_1[5] = uVar5;
      return;
    }
  }
LAB_10005590:
  FUN_10032f7f();
LAB_10005595:
  FUN_10001fb0();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100055a0 @ 100055a0