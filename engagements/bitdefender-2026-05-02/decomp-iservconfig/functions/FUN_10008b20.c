int __cdecl
FUN_10008b20(char *param_1,uint param_2,char *param_3,__crt_locale_pointers *param_4,char *param_5)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = (undefined4 *)FUN_10008b80();
  iVar2 = ___stdio_common_vsprintf_s(*puVar1,puVar1[1],param_1,param_2,param_3,param_4,param_5);
  if (iVar2 < 0) {
    iVar2 = -1;
  }
  return iVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_10008b60 @ 10008b60