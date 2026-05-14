void FUN_1001d51e(void)

{
  uint uVar1;
  undefined4 uVar2;
  void *pvVar3;
  code *pcVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  uint uVar9;
  void *pvVar10;
  uint unaff_EBP;
  undefined4 *unaff_ESI;
  undefined8 uVar11;
  undefined4 uStack00000008;
  
  uVar5 = *(undefined4 *)(unaff_EBP - 0x38);
  uVar6 = *(undefined4 *)(unaff_EBP - 0x34);
  uVar7 = *(undefined4 *)(unaff_EBP - 0x30);
  uVar8 = *(undefined4 *)(unaff_EBP - 0x2c);
  uVar1 = *(uint *)(unaff_EBP - 0x9c);
  *unaff_ESI = 0;
  uVar9 = 7;
  unaff_ESI[4] = 0;
  unaff_ESI[5] = 0;
  *(undefined2 *)(unaff_EBP - 0x38) = 0;
  uVar2 = *(undefined4 *)(unaff_EBP - 0x20);
  *unaff_ESI = uVar5;
  unaff_ESI[1] = uVar6;
  unaff_ESI[2] = uVar7;
  unaff_ESI[3] = uVar8;
  *(undefined8 *)(unaff_ESI + 4) = *(undefined8 *)(unaff_EBP - 0x28);
  *(undefined4 *)(unaff_EBP - 0x28) = 0;
  *(undefined4 *)(unaff_EBP - 0x24) = 7;
  unaff_ESI[6] = uVar2;
  if (0xf < uVar1) {
    pvVar3 = *(void **)(unaff_EBP - 0xb0);
    pvVar10 = pvVar3;
    if ((0xfff < uVar1 + 1) &&
       (pvVar10 = *(void **)((int)pvVar3 + -4), 0x1f < (uint)((int)pvVar3 + (-4 - (int)pvVar10))))
    goto LAB_1001d6be;
    FUN_1002e346(pvVar10);
    uVar9 = *(uint *)(unaff_EBP - 0x24);
  }
  uVar1 = *(uint *)(unaff_EBP - 0x40);
  *(undefined4 *)(unaff_EBP - 0xa0) = 0;
  *(undefined4 *)(unaff_EBP - 0x9c) = 0xf;
  *(undefined1 *)(unaff_EBP - 0xb0) = 0;
  if (7 < uVar1) {
    pvVar3 = *(void **)(unaff_EBP - 0x54);
    pvVar10 = pvVar3;
    if ((0xfff < uVar1 * 2 + 2) &&
       (pvVar10 = *(void **)((int)pvVar3 + -4), 0x1f < (uint)((int)pvVar3 + (-4 - (int)pvVar10))))
    goto LAB_1001d6be;
    FUN_1002e346(pvVar10);
    uVar9 = *(uint *)(unaff_EBP - 0x24);
  }
  *(undefined4 *)(unaff_EBP - 0x44) = 0;
  *(undefined4 *)(unaff_EBP - 0x40) = 7;
  *(undefined2 *)(unaff_EBP - 0x54) = 0;
  if (7 < uVar9) {
    pvVar3 = *(void **)(unaff_EBP - 0x38);
    pvVar10 = pvVar3;
    if ((0xfff < uVar9 * 2 + 2) &&
       (pvVar10 = *(void **)((int)pvVar3 + -4), 0x1f < (uint)((int)pvVar3 + (-4 - (int)pvVar10)))) {
LAB_1001d6be:
      uVar11 = FUN_10032f7f();
      _DAT_c91001d4 = (int *)uVar11;
      *_DAT_c91001d4 = *_DAT_c91001d4 + (int)((ulonglong)uVar11 >> 0x20);
      *_DAT_c91001d4 = *_DAT_c91001d4 + CONCAT31((int3)((ulonglong)uVar11 >> 0x28),0xd4);
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    }
    FUN_1002e346(pvVar10);
  }
  ExceptionList = *(void **)(unaff_EBP - 0xc);
  uStack00000008 = 0x1001d657;
  FUN_1002e315(*(uint *)(unaff_EBP - 0x1c) ^ unaff_EBP);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001d6e0 @ 1001d6e0