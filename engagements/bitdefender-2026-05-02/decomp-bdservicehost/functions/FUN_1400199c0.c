uint FUN_1400199c0(longlong param_1)

{
  int iVar1;
  byte *pbVar2;
  uint uVar3;
  longlong lVar4;
  uint uVar5;
  
  lVar4 = *(longlong *)(param_1 + 0x10);
  if (**(longlong **)(lVar4 + 0x38) != 0) {
    iVar1 = **(int **)(lVar4 + 0x50);
    if (0 < iVar1) {
      **(int **)(lVar4 + 0x50) = iVar1 + -1;
      pbVar2 = (byte *)**(longlong **)(lVar4 + 0x38);
      **(longlong **)(lVar4 + 0x38) = (longlong)(pbVar2 + 1);
      uVar3 = (uint)*pbVar2;
      goto LAB_140019a0b;
    }
  }
  uVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
LAB_140019a0b:
  if (uVar3 == 0xffffffff) {
    lVar4 = (longlong)*(int *)(**(longlong **)(param_1 + 8) + 4) +
            (longlong)*(longlong **)(param_1 + 8);
    uVar5 = 5;
    if (*(longlong *)(lVar4 + 0x48) != 0) {
      uVar5 = 1;
    }
    FUN_140002cd0(lVar4,uVar5 | *(uint *)(lVar4 + 0x10),'\0');
  }
  return uVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_140019a50 @ 140019a50