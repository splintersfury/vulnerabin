int * FUN_140002290(undefined8 param_1,int *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_14002d7f8(param_3);
  if (iVar1 == 0) {
    *param_2 = param_3;
    *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ac70;
    return param_2;
  }
  *param_2 = iVar1;
  *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ac90;
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400022f0 @ 1400022f0