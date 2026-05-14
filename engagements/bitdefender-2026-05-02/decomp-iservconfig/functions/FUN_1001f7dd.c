void FUN_1001f7dd(void)

{
  void *pvVar1;
  uint uVar2;
  code *pcVar3;
  void *pvVar4;
  uint unaff_EBP;
  undefined4 uStack00000008;
  
  pvVar1 = *(void **)(unaff_EBP - 0x34);
  if (7 < *(uint *)(unaff_EBP - 0x20)) {
    pvVar4 = pvVar1;
    if (0xfff < *(uint *)(unaff_EBP - 0x20) * 2 + 2) {
      pvVar4 = *(void **)((int)pvVar1 + -4);
      if (0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar4))) goto LAB_1001f85f;
    }
    FUN_1002e346(pvVar4);
  }
  uVar2 = *(uint *)(unaff_EBP - 0x38);
  *(undefined4 *)(unaff_EBP - 0x24) = 0;
  *(undefined4 *)(unaff_EBP - 0x20) = 7;
  *(undefined2 *)(unaff_EBP - 0x34) = 0;
  if (7 < uVar2) {
    pvVar1 = *(void **)(unaff_EBP - 0x4c);
    pvVar4 = pvVar1;
    if (0xfff < uVar2 * 2 + 2) {
      pvVar4 = *(void **)((int)pvVar1 + -4);
      if (0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar4))) {
LAB_1001f85f:
        FUN_10032f7f();
        FUN_10032f7f();
        FUN_10032f7f();
        FUN_10032f7f();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
    }
    FUN_1002e346(pvVar4);
  }
  *(undefined4 *)(unaff_EBP - 0x38) = 7;
  *(undefined4 *)(unaff_EBP - 0x3c) = 0;
  *(undefined2 *)(unaff_EBP - 0x4c) = 0;
  FUN_1000c320(unaff_EBP - 0x4a0);
  ExceptionList = *(void **)(unaff_EBP - 0xc);
  uStack00000008 = 0x1001f4c4;
  FUN_1002e315(*(uint *)(unaff_EBP - 0x1c) ^ unaff_EBP);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001f880 @ 1001f880