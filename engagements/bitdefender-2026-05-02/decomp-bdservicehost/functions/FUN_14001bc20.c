undefined8 FUN_14001bc20(longlong *param_1)

{
  int iVar1;
  
  if (param_1[0x10] != 0) {
    iVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,0xffffffff);
    if (iVar1 != -1) {
      iVar1 = fflush((FILE *)param_1[0x10]);
      if (iVar1 < 0) {
        return 0xffffffff;
      }
    }
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001bc70 @ 14001bc70