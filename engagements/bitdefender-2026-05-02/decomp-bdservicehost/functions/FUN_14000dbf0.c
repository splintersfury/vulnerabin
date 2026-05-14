ulonglong FUN_14000dbf0(longlong param_1,ushort param_2)

{
  longlong lVar1;
  int iVar2;
  ushort *puVar3;
  longlong lVar4;
  code *pcVar5;
  uint uVar6;
  void *pvVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  undefined8 *puVar10;
  undefined8 *puVar11;
  undefined8 *puVar12;
  
  if ((*(byte *)(param_1 + 0x70) & 2) != 0) {
    return 0xffff;
  }
  puVar10 = (undefined8 *)0x0;
  if (param_2 == 0xffff) {
    return 0;
  }
  uVar9 = **(ulonglong **)(param_1 + 0x40);
  iVar2 = **(int **)(param_1 + 0x58);
  uVar8 = uVar9 + (longlong)iVar2 * 2;
  if (uVar9 == 0) {
    puVar11 = (undefined8 *)**(longlong **)(param_1 + 0x18);
    puVar12 = puVar10;
LAB_14000dd0f:
    uVar8 = 0x40;
LAB_14000dd14:
    puVar10 = (undefined8 *)operator_new(uVar8);
  }
  else {
    if (uVar9 < uVar8) {
      **(int **)(param_1 + 0x58) = iVar2 + -1;
      puVar3 = (ushort *)**(longlong **)(param_1 + 0x40);
      **(longlong **)(param_1 + 0x40) = (longlong)(puVar3 + 1);
      *puVar3 = param_2;
      *(ulonglong *)(param_1 + 0x68) = uVar9 + 2;
      return (ulonglong)param_2;
    }
    puVar11 = (undefined8 *)**(longlong **)(param_1 + 0x18);
    puVar12 = (undefined8 *)((longlong)(uVar8 - (longlong)puVar11) >> 1);
    if (puVar12 < (undefined8 *)0x20) goto LAB_14000dd0f;
    if (puVar12 < (undefined8 *)0x3fffffff) {
      if (0x7fffffffffffffff < (ulonglong)((longlong)puVar12 * 2)) {
LAB_14000de23:
        FUN_140001670();
        pcVar5 = (code *)swi(3);
        uVar8 = (*pcVar5)();
        return uVar8;
      }
      uVar8 = (longlong)puVar12 * 4;
      if (0xfff < uVar8) {
        uVar9 = uVar8 + 0x27;
        if (uVar9 <= uVar8) goto LAB_14000de23;
        goto LAB_14000dce9;
      }
      if (uVar8 == 0) goto LAB_14000dd1f;
      goto LAB_14000dd14;
    }
    if ((undefined8 *)0x7ffffffe < puVar12) {
      return 0xffff;
    }
    uVar8 = 0xfffffffe;
    uVar9 = 0x100000025;
LAB_14000dce9:
    pvVar7 = operator_new(uVar9);
    if (pvVar7 == (void *)0x0) goto LAB_14000de1d;
    puVar10 = (undefined8 *)((longlong)pvVar7 + 0x27U & 0xffffffffffffffe0);
    puVar10[-1] = pvVar7;
  }
LAB_14000dd1f:
  uVar9 = (longlong)puVar12 * 2;
  FUN_1400316b0(puVar10,puVar11,uVar9);
  lVar1 = uVar9 + (longlong)puVar10;
  *(longlong *)(param_1 + 0x68) = lVar1 + 2;
  **(undefined8 **)(param_1 + 0x20) = puVar10;
  **(longlong **)(param_1 + 0x40) = lVar1;
  **(undefined4 **)(param_1 + 0x58) = (int)((longlong)((uVar8 - lVar1) + (longlong)puVar10) >> 1);
  if ((*(byte *)(param_1 + 0x70) & 4) == 0) {
    lVar4 = *(longlong *)(param_1 + 0x68);
    lVar1 = **(longlong **)(param_1 + 0x38);
    **(undefined8 **)(param_1 + 0x18) = puVar10;
    lVar1 = (longlong)puVar10 + (lVar1 - (longlong)puVar11 >> 1) * 2;
    **(longlong **)(param_1 + 0x38) = lVar1;
    **(undefined4 **)(param_1 + 0x50) = (int)(lVar4 - lVar1 >> 1);
  }
  else {
    **(undefined8 **)(param_1 + 0x18) = puVar10;
    **(undefined8 **)(param_1 + 0x38) = 0;
    **(undefined4 **)(param_1 + 0x50) = (int)((longlong)puVar10 >> 1);
  }
  uVar6 = *(uint *)(param_1 + 0x70);
  if ((uVar6 & 1) != 0) {
    if ((0xfff < uVar9) && (0x1f < (ulonglong)((longlong)puVar11 + (-8 - puVar11[-1])))) {
LAB_14000de1d:
      FUN_140035d28();
      pcVar5 = (code *)swi(3);
      uVar8 = (*pcVar5)();
      return uVar8;
    }
    FUN_14002f180();
    uVar6 = *(uint *)(param_1 + 0x70);
  }
  *(uint *)(param_1 + 0x70) = uVar6 | 1;
  **(int **)(param_1 + 0x58) = **(int **)(param_1 + 0x58) + -1;
  puVar3 = (ushort *)**(longlong **)(param_1 + 0x40);
  **(longlong **)(param_1 + 0x40) = (longlong)(puVar3 + 1);
  *puVar3 = param_2;
  return (ulonglong)param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000de30 @ 14000de30