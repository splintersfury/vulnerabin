void FUN_10008243(void)

{
  int *piVar1;
  bool bVar2;
  void *this;
  uint uVar3;
  int *unaff_EBX;
  int unaff_EBP;
  uint unaff_ESI;
  
  uVar3 = 4;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  this = (void *)(*(int *)(*unaff_EBX + 4) + (int)unaff_EBX);
  if (*(int *)((int)this + 0x38) != 0) {
    uVar3 = 0;
  }
  FUN_10002bd0(this,uVar3 | *(uint *)(*(int *)(*unaff_EBX + 4) + 0xc + (int)unaff_EBX) | unaff_ESI,
               '\0');
  *(undefined4 *)(unaff_EBP + -4) = 4;
  bVar2 = ___uncaught_exception();
  if (!bVar2) {
    FUN_10007e90(*(int **)(unaff_EBP + -0x40));
  }
  *(undefined1 *)(unaff_EBP + -4) = 5;
  piVar1 = *(int **)(*(int *)(**(int **)(unaff_EBP + -0x40) + 4) + 0x38 +
                    (int)*(int **)(unaff_EBP + -0x40));
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))();
  }
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100082c0 @ 100082c0