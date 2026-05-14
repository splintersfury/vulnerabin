void FUN_10024780(void)

{
  int *piVar1;
  bool bVar2;
  void *this;
  uint uVar3;
  int unaff_EBP;
  uint unaff_ESI;
  int *unaff_EDI;
  
  uVar3 = 4;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  this = (void *)(*(int *)(*unaff_EDI + 4) + (int)unaff_EDI);
  if (*(int *)((int)this + 0x38) != 0) {
    uVar3 = 0;
  }
  FUN_10002bd0(this,uVar3 | *(uint *)(*(int *)(*unaff_EDI + 4) + 0xc + (int)unaff_EDI) | unaff_ESI,
               '\0');
  *(undefined4 *)(unaff_EBP + -4) = 3;
  bVar2 = ___uncaught_exception();
  if (!bVar2) {
    FUN_10007e90(*(int **)(unaff_EBP + -0x30));
  }
  *(undefined1 *)(unaff_EBP + -4) = 4;
  piVar1 = *(int **)(*(int *)(**(int **)(unaff_EBP + -0x30) + 4) + 0x38 +
                    (int)*(int **)(unaff_EBP + -0x30));
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))();
  }
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100247f0 @ 100247f0