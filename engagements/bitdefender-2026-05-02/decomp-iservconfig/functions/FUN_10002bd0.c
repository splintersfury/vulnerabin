void __thiscall FUN_10002bd0(void *this,uint param_1,char param_2)

{
  undefined4 *puVar1;
  uint *extraout_EDX;
  undefined4 local_24 [2];
  int local_1c [6];
  
  *(uint *)((int)this + 0xc) = param_1 & 0x17;
  if ((*(uint *)((int)this + 0x10) & param_1 & 0x17) == 0) {
    return;
  }
  if (param_2 == '\0') {
    puVar1 = FUN_100020e0(local_24);
    FUN_10002ba0(local_1c,extraout_EDX,puVar1);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(local_1c,&DAT_1006747c);
  }
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8((int *)0x0,(byte *)0x0);
}


// FUNCTION_END

// FUNCTION_START: FUN_10002c40 @ 10002c40