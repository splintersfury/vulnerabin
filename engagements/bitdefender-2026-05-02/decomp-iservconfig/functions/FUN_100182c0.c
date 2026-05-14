char * __fastcall FUN_100182c0(undefined4 *param_1)

{
  char *pcVar1;
  int local_44 [7];
  uint local_28 [6];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f33d;
  local_10 = ExceptionList;
  pcVar1 = (char *)*param_1;
  if (*pcVar1 == '\x01') {
    pcVar1 = (char *)(param_1[1] + 0x28);
  }
  else {
    if (*pcVar1 == '\x02') {
      return (char *)param_1[2];
    }
    if (param_1[3] != 0) {
      ExceptionList = &local_10;
      FUN_10005690(local_28,(uint *)"cannot get value");
      local_8 = 0;
      FUN_1000abb0(local_44,0xd6,local_28);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_44,&DAT_1006750c);
    }
  }
  return pcVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018360 @ 10018360