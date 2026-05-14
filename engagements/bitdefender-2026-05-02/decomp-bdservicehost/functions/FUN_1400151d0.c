int FUN_1400151d0(char *param_1,__uint64 param_2,char *param_3,undefined8 param_4)

{
  int iVar1;
  __uint64 *p_Var2;
  undefined8 local_res20;
  
  local_res20 = param_4;
  p_Var2 = (__uint64 *)FUN_140015230();
  iVar1 = __stdio_common_vsprintf_s
                    (*p_Var2,param_1,param_2,param_3,(__crt_locale_pointers *)0x0,
                     (char *)&local_res20);
  if (iVar1 < 0) {
    iVar1 = -1;
  }
  return iVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140015230 @ 140015230