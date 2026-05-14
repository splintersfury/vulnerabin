void __fastcall FUN_10003e10(int *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  FUN_100047f0(param_1 + 0x4d);
  FUN_100047f0(param_1 + 0x46);
  if (7 < (uint)param_1[0x45]) {
    pvVar1 = (void *)param_1[0x40];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0x45] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_100040d9;
    FUN_1002e346(pvVar3);
  }
  param_1[0x44] = 0;
  param_1[0x45] = 7;
  *(undefined2 *)(param_1 + 0x40) = 0;
  FUN_100047f0(param_1 + 0x39);
  FUN_100047f0(param_1 + 0x32);
  FUN_100047f0(param_1 + 0x2b);
  if (7 < (uint)param_1[0x29]) {
    pvVar1 = (void *)param_1[0x24];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0x29] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_100040d9;
    FUN_1002e346(pvVar3);
  }
  param_1[0x28] = 0;
  param_1[0x29] = 7;
  *(undefined2 *)(param_1 + 0x24) = 0;
  if (7 < (uint)param_1[0x23]) {
    pvVar1 = (void *)param_1[0x1e];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0x23] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_100040d9;
    FUN_1002e346(pvVar3);
  }
  param_1[0x22] = 0;
  param_1[0x23] = 7;
  *(undefined2 *)(param_1 + 0x1e) = 0;
  if (7 < (uint)param_1[0x1d]) {
    pvVar1 = (void *)param_1[0x18];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0x1d] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_100040d9;
    FUN_1002e346(pvVar3);
  }
  param_1[0x1c] = 0;
  param_1[0x1d] = 7;
  *(undefined2 *)(param_1 + 0x18) = 0;
  if (7 < (uint)param_1[0x17]) {
    pvVar1 = (void *)param_1[0x12];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0x17] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_100040d9;
    FUN_1002e346(pvVar3);
  }
  param_1[0x16] = 0;
  param_1[0x17] = 7;
  *(undefined2 *)(param_1 + 0x12) = 0;
  if (7 < (uint)param_1[0x11]) {
    pvVar1 = (void *)param_1[0xc];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0x11] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_100040d9;
    FUN_1002e346(pvVar3);
  }
  param_1[0x10] = 0;
  param_1[0x11] = 7;
  *(undefined2 *)(param_1 + 0xc) = 0;
  if (7 < (uint)param_1[0xb]) {
    pvVar1 = (void *)param_1[6];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0xb] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_100040d9;
    FUN_1002e346(pvVar3);
  }
  param_1[10] = 0;
  param_1[0xb] = 7;
  *(undefined2 *)(param_1 + 6) = 0;
  if (7 < (uint)param_1[5]) {
    pvVar1 = (void *)*param_1;
    pvVar3 = pvVar1;
    if ((0xfff < param_1[5] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
LAB_100040d9:
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pvVar3);
  }
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100040e0 @ 100040e0