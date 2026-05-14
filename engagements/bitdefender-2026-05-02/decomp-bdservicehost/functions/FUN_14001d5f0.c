void FUN_14001d5f0(longlong param_1)

{
  int *piVar1;
  int iVar2;
  longlong lVar3;
  code *pcVar4;
  
  if (0xf < *(ulonglong *)(param_1 + 0x60)) {
    if ((0xfff < *(ulonglong *)(param_1 + 0x60) + 1) &&
       (0x1f < (*(longlong *)(param_1 + 0x48) - *(longlong *)(*(longlong *)(param_1 + 0x48) + -8)) -
               8U)) goto LAB_14001d6da;
    FUN_14002f180();
  }
  *(undefined8 *)(param_1 + 0x60) = 0xf;
  *(undefined8 *)(param_1 + 0x58) = 0;
  *(undefined1 *)(param_1 + 0x48) = 0;
  lVar3 = *(longlong *)(param_1 + 0x30);
  if (lVar3 != 0) {
    if ((0xfff < (ulonglong)(*(longlong *)(param_1 + 0x40) - lVar3)) &&
       (0x1f < (lVar3 - *(longlong *)(lVar3 + -8)) - 8U)) {
LAB_14001d6da:
      FUN_140035d28();
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    }
    FUN_14002f180();
    *(undefined8 *)(param_1 + 0x30) = 0;
    *(undefined8 *)(param_1 + 0x38) = 0;
    *(undefined8 *)(param_1 + 0x40) = 0;
  }
  lVar3 = *(longlong *)(param_1 + 8);
  if (lVar3 != 0) {
    LOCK();
    piVar1 = (int *)(lVar3 + 8);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar2 == 1) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar3);
      LOCK();
      piVar1 = (int *)(lVar3 + 0xc);
      iVar2 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar2 == 1) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar3);
      }
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d6e0 @ 14001d6e0