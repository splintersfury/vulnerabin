int FUN_14002a640(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  ulonglong *puVar2;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  puVar2 = (ulonglong *)FUN_140015230();
  iVar1 = common_vsprintf<class___crt_stdio_output::standard_base,char>
                    (*puVar2 | 2,(char *)0x0,0,param_1,(__crt_locale_pointers *)0x0,
                     (char *)&local_res10);
  if (iVar1 < 0) {
    iVar1 = -1;
  }
  return iVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a6a0 @ 14002a6a0