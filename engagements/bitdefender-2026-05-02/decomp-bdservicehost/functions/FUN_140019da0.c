void FUN_140019da0(longlong param_1)

{
  longlong lVar1;
  code *pcVar2;
  longlong lVar3;
  
  lVar1 = *(longlong *)(param_1 + 0x18);
  lVar3 = lVar1;
  if ((0xfff < (*(longlong *)(param_1 + 0x20) - lVar1 & 0xfffffffffffffff8U)) &&
     (lVar3 = *(longlong *)(lVar1 + -8), 0x1f < (lVar1 - lVar3) - 8U)) {
    FUN_140035d28();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  FUN_14002f180();
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 0x20) = 0;
  *(undefined8 *)(param_1 + 0x28) = 0;
  FUN_140022010(lVar3,*(undefined8 **)(param_1 + 8));
  FUN_14002f180();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140019e10 @ 140019e10