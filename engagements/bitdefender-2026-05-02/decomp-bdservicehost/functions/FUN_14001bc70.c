longlong FUN_14001bc70(longlong param_1,char *param_2,size_t param_3)

{
  int iVar1;
  
  if ((param_2 == (char *)0x0) && (param_3 == 0)) {
    iVar1 = 4;
  }
  else {
    iVar1 = 0;
  }
  if (*(FILE **)(param_1 + 0x80) != (FILE *)0x0) {
    iVar1 = setvbuf(*(FILE **)(param_1 + 0x80),param_2,iVar1,param_3);
    if (iVar1 == 0) {
      FUN_14001d8d0(param_1,*(longlong *)(param_1 + 0x80),1);
      return param_1;
    }
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001bcd0 @ 14001bcd0