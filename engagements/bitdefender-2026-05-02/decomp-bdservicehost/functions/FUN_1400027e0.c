undefined2 *
FUN_1400027e0(longlong *param_1,undefined2 param_2,undefined2 *param_3,undefined2 *param_4)

{
  char cVar1;
  
  if (param_3 != param_4) {
    do {
      cVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,param_2,*param_3);
      if (cVar1 != '\0') {
        return param_3;
      }
      param_3 = param_3 + 1;
    } while (param_3 != param_4);
  }
  return param_3;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002840 @ 140002840