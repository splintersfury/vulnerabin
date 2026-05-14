void FUN_1002bd54(void)

{
  int *piVar1;
  bool bVar2;
  uint uVar3;
  void *this;
  int *unaff_EBX;
  int unaff_EBP;
  uint unaff_EDI;
  
  *(undefined4 *)(unaff_EBP + -4) = 0;
  uVar3 = 4;
  this = (void *)(*(int *)(*unaff_EBX + 4) + (int)unaff_EBX);
  if (*(int *)((int)this + 0x38) != 0) {
    uVar3 = 0;
  }
  FUN_10002bd0(this,uVar3 | *(uint *)((int)this + 0xc) | unaff_EDI,'\0');
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

// FUNCTION_START: FUN_1002bdd0 @ 1002bdd0