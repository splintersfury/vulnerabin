void FUN_1002bb25(void)

{
  int iVar1;
  int *piVar2;
  bool bVar3;
  void *this;
  uint uVar4;
  int *unaff_EBX;
  int unaff_EBP;
  uint unaff_ESI;
  
  *(undefined4 *)(unaff_EBP + -4) = 0;
  uVar4 = 4;
  iVar1 = *(int *)(*unaff_EBX + 4);
  *(undefined4 *)(iVar1 + 0x20 + (int)unaff_EBX) = 0;
  *(undefined4 *)(iVar1 + 0x24 + (int)unaff_EBX) = 0;
  this = (void *)(*(int *)(*unaff_EBX + 4) + (int)unaff_EBX);
  if (*(int *)((int)this + 0x38) != 0) {
    uVar4 = 0;
  }
  FUN_10002bd0(this,uVar4 | *(uint *)(*(int *)(*unaff_EBX + 4) + 0xc + (int)unaff_EBX) | unaff_ESI,
               '\0');
  *(undefined4 *)(unaff_EBP + -4) = 4;
  bVar3 = ___uncaught_exception();
  if (!bVar3) {
    FUN_10007e90(*(int **)(unaff_EBP + -0x30));
  }
  *(undefined1 *)(unaff_EBP + -4) = 5;
  piVar2 = *(int **)(*(int *)(**(int **)(unaff_EBP + -0x30) + 4) + 0x38 +
                    (int)*(int **)(unaff_EBP + -0x30));
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))();
  }
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002bbb0 @ 1002bbb0