void FUN_140025870(longlong *param_1)

{
  longlong lVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  longlong local_28;
  ulonglong uStack_20;
  longlong local_18 [3];
  
  uVar2 = param_1[3];
  if (((longlong)uVar2 < 0) && (uVar2 != 0)) {
    lVar1 = -((~uVar2 >> 5) * 4 + 4);
  }
  else {
    lVar1 = (uVar2 >> 5) * 4;
  }
  uVar3 = (ulonglong)((uint)uVar2 & 0x1f);
  uVar2 = uVar3 - 1;
  if (uVar3 == 0) {
    local_28 = -((~uVar2 >> 5) * 4 + 4);
  }
  else {
    local_28 = (uVar2 >> 5) * 4;
  }
  local_28 = *param_1 + lVar1 + local_28;
  uStack_20 = (ulonglong)((uint)uVar2 & 0x1f);
  FUN_140025f10(param_1,local_18,&local_28);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140025910 @ 140025910