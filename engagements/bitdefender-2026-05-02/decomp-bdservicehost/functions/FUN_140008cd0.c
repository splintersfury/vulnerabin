void FUN_140008cd0(longlong param_1)

{
  longlong lVar1;
  
  if ((*(char *)(param_1 + 0x68) != '\0') && (lVar1 = *(longlong *)(param_1 + 0x60), lVar1 != 0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar1,lVar1 != param_1 + 0x28);
    *(undefined8 *)(param_1 + 0x60) = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: InitializeCriticalSectionEx @ 140008d10