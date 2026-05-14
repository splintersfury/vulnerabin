undefined2 __fastcall FUN_10005100(int *param_1)

{
  undefined2 *puVar1;
  short sVar2;
  
  sVar2 = (**(code **)(*param_1 + 0x18))();
  if (sVar2 == -1) {
    return 0xffff;
  }
  *(int *)param_1[0xb] = *(int *)param_1[0xb] + -1;
  puVar1 = *(undefined2 **)param_1[7];
  *(undefined2 **)param_1[7] = puVar1 + 1;
  return *puVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005130 @ 10005130