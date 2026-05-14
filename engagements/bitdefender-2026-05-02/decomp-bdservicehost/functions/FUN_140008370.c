void FUN_140008370(void)

{
  longlong lVar1;
  code *pcVar2;
  longlong *plVar3;
  longlong lVar4;
  
  plVar3 = (longlong *)FUN_140008300();
  lVar4 = *plVar3;
  lVar1 = plVar3[1];
  while( true ) {
    if (lVar4 == lVar1) {
      return;
    }
    if (*(longlong *)(lVar4 + 0x38) == 0) break;
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    lVar4 = lVar4 + 0x40;
  }
  FUN_14002d6d4();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400083c0 @ 1400083c0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */