int FUN_14002a5e0(char *param_1,__uint64 param_2,char *param_3,undefined8 param_4)

{
  int iVar1;
  ulonglong *puVar2;
  undefined8 local_res20;
  
  local_res20 = param_4;
  puVar2 = (ulonglong *)FUN_140015230();
  iVar1 = common_vsprintf<class___crt_stdio_output::standard_base,char>
                    (*puVar2 | 2,param_1,param_2,param_3,(__crt_locale_pointers *)0x0,
                     (char *)&local_res20);
  if (iVar1 < 0) {
    iVar1 = -1;
  }
  return iVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a640 @ 14002a640