void FUN_140012980(longlong *param_1)

{
  longlong lVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  
  lVar1 = *param_1;
  if ((lVar1 != 0) && (puVar2 = *(undefined8 **)(lVar1 + -0xc), puVar2 != (undefined8 *)0x0)) {
    if ((*(int *)(lVar1 + -0x10) != 0xabcd) ||
       ((*(int *)(lVar1 + -4) != 0xabcd || (*(int *)(lVar1 + 2 + puVar2[2] * 2) != 0xabcd)))) {
                    /* WARNING: Subroutine does not return */
      _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
    }
    if (puVar2 != (undefined8 *)0x0) {
      if (*(char *)(puVar2 + 4) != '\0') {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(*puVar2,lVar1 + -0x10);
      }
      uVar3 = *puVar2;
      if (*(char *)((longlong)puVar2 + 0x21) != '\0') {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar3,puVar2);
      }
      (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar3);
    }
  }
  *param_1 = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140012a30 @ 140012a30