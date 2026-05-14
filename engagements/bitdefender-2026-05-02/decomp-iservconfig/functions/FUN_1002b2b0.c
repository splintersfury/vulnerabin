void __fastcall FUN_1002b2b0(int *param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar1 = param_1[1];
  iVar2 = *param_1;
  piVar3 = (int *)FUN_1002b390(3);
  FUN_1002b580((int *)*param_1,(int *)param_1[1],piVar3);
  FUN_1002b300(param_1,(int)piVar3,(iVar1 - iVar2) / 0x18,3);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002b300 @ 1002b300