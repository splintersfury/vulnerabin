void __fastcall FUN_10017fb0(int *param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int local_10 [3];
  
  uVar4 = param_1[3];
  if (((int)uVar4 < 0) && (uVar4 != 0)) {
    iVar2 = -((~uVar4 >> 5) * 4 + 4);
  }
  else {
    iVar2 = (uVar4 >> 5) * 4;
  }
  uVar1 = (uVar4 & 0x1f) - 1;
  if ((uVar4 & 0x1f) == 0) {
    iVar3 = -((~uVar1 >> 5) * 4 + 4);
  }
  else {
    iVar3 = (uVar1 >> 5) * 4;
  }
  FUN_10018550(param_1,local_10,*param_1 + iVar2 + iVar3,uVar1 & 0x1f);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018020 @ 10018020