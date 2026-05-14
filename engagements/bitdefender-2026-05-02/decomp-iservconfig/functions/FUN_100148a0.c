uint __fastcall FUN_100148a0(byte *param_1,uint param_2,byte *param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  
  uVar2 = param_2;
  if (param_4 < param_2) {
    uVar2 = param_4;
  }
  while (uVar1 = uVar2 - 4, 3 < uVar2) {
    if (*(int *)param_1 != *(int *)param_3) goto LAB_100148ce;
    param_1 = param_1 + 4;
    param_3 = param_3 + 4;
    uVar2 = uVar1;
  }
  if (uVar1 != 0xfffffffc) {
LAB_100148ce:
    bVar3 = *param_1 < *param_3;
    if ((*param_1 != *param_3) ||
       ((uVar1 != 0xfffffffd &&
        ((bVar3 = param_1[1] < param_3[1], param_1[1] != param_3[1] ||
         ((uVar1 != 0xfffffffe &&
          ((bVar3 = param_1[2] < param_3[2], param_1[2] != param_3[2] ||
           ((uVar1 != 0xffffffff && (bVar3 = param_1[3] < param_3[3], param_1[3] != param_3[3]))))))
         )))))) {
      uVar2 = -(uint)bVar3 | 1;
      goto LAB_10014904;
    }
  }
  uVar2 = 0;
LAB_10014904:
  if (uVar2 == 0) {
    if (param_2 < param_4) {
      return 0xffffffff;
    }
    uVar2 = (uint)(param_4 < param_2);
  }
  return uVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014920 @ 10014920